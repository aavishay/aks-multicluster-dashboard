//! Interactive `kubectl exec -it` equivalent: a PTY-backed shell in a pod
//! container.
//!
//! Shaped like the log streams in `k8s.rs` — a `start_*` that spawns pumps and
//! returns an id, a registry keyed by that id, a `stop_*` that aborts — with
//! one difference that drives the rest of this module: logs are one-way, and a
//! terminal is not. So a session also owns a writer for stdin and a sender for
//! terminal size, and both have to be reachable from a later Tauri command.
//!
//! kube hands out stdin as `impl AsyncWrite + Unpin`, which cannot sit in a
//! `Mutex` that a command locks and awaits across. Rather than fight that, the
//! writer is moved into its own task and fed over an mpsc channel; `send_stdin`
//! only has to push bytes into that channel.
//!
//! Everything here requires write mode. Exec is arbitrary code execution
//! inside a container — strictly more dangerous than the scale/restart/delete
//! operations already behind the same gate.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use base64::Engine;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, AttachParams, TerminalSize};
use futures::channel::mpsc as futures_mpsc;
use futures::SinkExt;
use tauri::ipc::Channel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

use crate::kubeconfig::client_for_context;
use crate::mutate::require_write;

/// One read from the remote stdout. 8 KiB matches what a terminal emulator
/// comfortably absorbs per frame; larger reads just add latency before the
/// first byte reaches the screen.
const READ_CHUNK: usize = 8 * 1024;

/// Bounded so a program spewing output faster than the webview can render it
/// applies backpressure to the reader rather than growing without limit. A
/// terminal that falls seconds behind is worse than one that pauses.
const STDIN_QUEUE: usize = 64;

#[derive(Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ExecEvent {
    /// Terminal bytes, base64-encoded.
    ///
    /// Base64 and not a `String`, because this is a byte stream and not text:
    /// an escape sequence or a multi-byte UTF-8 character can and does land
    /// across a read boundary. Decoding each chunk lossily here would replace
    /// the split halves with U+FFFD and corrupt the stream permanently, so the
    /// bytes are carried verbatim and handed to the terminal emulator, which
    /// reassembles them.
    Output { data: String },
    /// The remote process ended, or the connection did. Terminal either way —
    /// no further `Output` follows.
    Exit { message: String },
}

struct Session {
    stdin: mpsc::Sender<Vec<u8>>,
    /// `None` when the server did not negotiate the resize channel, which is
    /// what happens for a non-TTY exec. Resizes are then silently dropped
    /// rather than failing the caller.
    ///
    /// A `futures` sender and not a tokio one: this comes straight from
    /// `AttachedProcess::terminal_size()`, whose own alias for it is private.
    resize: Option<futures_mpsc::Sender<TerminalSize>>,
    aborts: Vec<AbortHandle>,
}

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static SESSIONS: OnceLock<Mutex<HashMap<u64, Session>>> = OnceLock::new();

fn sessions() -> &'static Mutex<HashMap<u64, Session>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Starts a shell and returns the session id used by every other call here.
///
/// `command` is passed as argv with no shell wrapping, so the caller picks the
/// shell (`["/bin/sh"]`, `["/bin/bash", "-l"]`). A container without that
/// binary fails on the remote side; there is no fallback, for the same reason
/// `kubectl exec` has none — silently running a different program than asked
/// for is worse than a clear error.
#[allow(clippy::too_many_arguments)]
pub async fn start_pod_exec(
    context_name: &str,
    namespace: &str,
    pod_name: &str,
    container: &str,
    command: Vec<String>,
    cols: u16,
    rows: u16,
    on_event: Channel<ExecEvent>,
) -> Result<u64, String> {
    require_write()?;

    if command.is_empty() {
        return Err("No command given for the exec session.".to_string());
    }

    let client = client_for_context(context_name).await?;
    let pods: Api<Pod> = Api::namespaced(client, namespace);

    // `interactive_tty()` is stdin+stdout+tty with stderr off. stderr *must*
    // be off: kube rejects `tty && stderr` because the protocol cannot
    // multiplex a separate error stream over a PTY — a real terminal merges
    // them onto one, and so does this.
    let params = AttachParams::interactive_tty().container(container);

    let mut process = pods
        .exec(pod_name, command, &params)
        .await
        .map_err(|e| format!("Could not open a shell in {pod_name}/{container}: {e}"))?;

    let mut remote_stdout = process
        .stdout()
        .ok_or_else(|| "The exec session came back without stdout.".to_string())?;
    let mut remote_stdin = process
        .stdin()
        .ok_or_else(|| "The exec session came back without stdin.".to_string())?;
    let resize = process.terminal_size();

    let id = NEXT_SESSION_ID.fetch_add(1, Ordering::SeqCst);

    // stdout -> frontend.
    let output_channel = on_event.clone();
    let stdout_pump = tokio::spawn(async move {
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            match remote_stdout.read(&mut buf).await {
                // A clean EOF: the process closed its side. The exit event is
                // emitted by the watcher below, which has the status.
                Ok(0) => return,
                Ok(n) => {
                    let data = base64::engine::general_purpose::STANDARD.encode(&buf[..n]);
                    // A send failure means the webview dropped the channel —
                    // the panel was closed. Stop reading rather than spinning.
                    if output_channel.send(ExecEvent::Output { data }).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });

    // frontend -> stdin.
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(STDIN_QUEUE);
    let stdin_pump = tokio::spawn(async move {
        while let Some(bytes) = stdin_rx.recv().await {
            if remote_stdin.write_all(&bytes).await.is_err() {
                return;
            }
            // Flushed per message, not per newline: a shell in raw mode wants
            // each keystroke immediately, and control characters (^C, tab
            // completion) are useless if they sit in a buffer.
            if remote_stdin.flush().await.is_err() {
                return;
            }
        }
    });

    // Watches for the process ending so the panel can say so, rather than
    // going quiet and leaving the reader unsure whether the shell died or is
    // merely idle.
    let exit_channel = on_event;
    let exit_watch = tokio::spawn(async move {
        let message = match process.join().await {
            Ok(()) => "Session ended.".to_string(),
            Err(e) => format!("Session ended: {e}"),
        };
        let _ = exit_channel.send(ExecEvent::Exit { message });
    });

    let session = Session {
        stdin: stdin_tx,
        resize,
        aborts: vec![
            stdout_pump.abort_handle(),
            stdin_pump.abort_handle(),
            exit_watch.abort_handle(),
        ],
    };
    sessions().lock().unwrap().insert(id, session);

    // The shell computes its first prompt from the size it is told at startup,
    // so send the real one before the user can type.
    resize_pod_exec(id, cols, rows).await;

    Ok(id)
}

/// Feeds keystrokes to the remote shell. `data` is base64, for the same
/// byte-exactness reason as `ExecEvent::Output`.
pub async fn send_pod_exec_stdin(session_id: u64, data: String) -> Result<(), String> {
    require_write()?;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data.as_bytes())
        .map_err(|e| format!("Keystrokes were not valid base64: {e}"))?;

    // Cloned out of the map rather than held across the await: the registry
    // mutex is a std Mutex, and its guard cannot cross an await point.
    let stdin = {
        let map = sessions().lock().unwrap();
        match map.get(&session_id) {
            Some(s) => s.stdin.clone(),
            None => return Err("That shell session is no longer open.".to_string()),
        }
    };

    stdin
        .send(bytes)
        .await
        .map_err(|_| "That shell session is no longer accepting input.".to_string())
}

/// Tells the remote PTY its new size, so full-screen programs redraw correctly.
///
/// Deliberately infallible: a resize is cosmetic, it races with the session
/// closing, and there is nothing useful for the caller to do about a failure.
pub async fn resize_pod_exec(session_id: u64, cols: u16, rows: u16) {
    // Cloned rather than borrowed: sending on a Sink needs `&mut`, and the
    // registry's guard cannot be held across the await. A clone shares the
    // same underlying channel, so the resize still reaches the session.
    let mut sender = {
        let map = sessions().lock().unwrap();
        match map.get(&session_id).and_then(|s| s.resize.clone()) {
            Some(tx) => tx,
            None => return,
        }
    };
    let _ = sender
        .send(TerminalSize {
            width: cols,
            height: rows,
        })
        .await;
}

/// Ends a session and drops its tasks. Safe to call for an id that has already
/// gone, so the frontend can call it unconditionally when a panel closes.
pub fn stop_pod_exec(session_id: u64) {
    let Some(session) = sessions().lock().unwrap().remove(&session_id) else {
        return;
    };
    for abort in session.aborts {
        abort.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stopping_an_unknown_session_is_a_no_op() {
        // The frontend calls this whenever a panel closes, including for a
        // session that already ended on its own.
        stop_pod_exec(u64::MAX);
    }

    #[tokio::test]
    async fn stdin_for_an_unknown_session_reports_rather_than_panics() {
        // Write mode is off by default in tests, so this exercises the gate.
        let err = send_pod_exec_stdin(u64::MAX, String::new()).await.unwrap_err();
        assert!(err.contains("Read-only"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn resizing_an_unknown_session_is_a_no_op() {
        resize_pod_exec(u64::MAX, 80, 24).await;
    }

    /// Proves the parts that only a real API server can prove: that the `ws`
    /// feature's WebSocket upgrade completes through AKS (whose auth is an
    /// exec-plugin `kubelogin` token, not a static credential), that
    /// `interactive_tty()` is accepted, and that the server negotiates the
    /// resize channel a PTY needs.
    ///
    /// Ignored by default and env-driven rather than hardcoded, so CI — which
    /// has no cluster — skips it and it is not pinned to one pod's lifetime:
    ///
    ///   EXEC_TEST_CONTEXT=aks-dev-weu-ng EXEC_TEST_NS=apisix \
    ///   EXEC_TEST_POD=some-pod EXEC_TEST_CONTAINER=some-container \
    ///   cargo test --manifest-path src-tauri/Cargo.toml exec_against_a_live_cluster -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a reachable cluster; set EXEC_TEST_* to run"]
    async fn exec_against_a_live_cluster() {
        let (Ok(context), Ok(ns), Ok(pod), Ok(container)) = (
            std::env::var("EXEC_TEST_CONTEXT"),
            std::env::var("EXEC_TEST_NS"),
            std::env::var("EXEC_TEST_POD"),
            std::env::var("EXEC_TEST_CONTAINER"),
        ) else {
            eprintln!("EXEC_TEST_* not set — skipping");
            return;
        };

        let client = client_for_context(&context).await.expect("client for context");
        let pods: Api<Pod> = Api::namespaced(client, &ns);
        let params = AttachParams::interactive_tty().container(&container);

        let mut process = pods
            .exec(&pod, vec!["/bin/sh", "-c", "echo EXEC_OK"], &params)
            .await
            .expect("exec should upgrade to a websocket");

        assert!(
            process.terminal_size().is_some(),
            "a tty exec must negotiate the resize channel"
        );

        let mut stdout = process.stdout().expect("stdout");
        let mut got = Vec::new();
        let mut buf = vec![0u8; READ_CHUNK];
        // Bounded so a hung read fails the test instead of hanging it.
        let read = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => {
                        got.extend_from_slice(&buf[..n]);
                        if String::from_utf8_lossy(&got).contains("EXEC_OK") {
                            return;
                        }
                    }
                    Err(e) => panic!("read failed: {e}"),
                }
            }
        })
        .await;
        assert!(read.is_ok(), "timed out waiting for output");

        let text = String::from_utf8_lossy(&got);
        assert!(text.contains("EXEC_OK"), "unexpected output: {text:?}");
    }

    #[test]
    fn output_events_carry_base64_not_lossy_text() {
        // A byte that is not valid UTF-8 on its own — the second half of a
        // multi-byte character split across reads. It has to survive.
        let raw = [0x1b, 0x5b, 0x33, 0x31, 0x6d, 0xf0, 0x9f];
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .expect("round-trips");
        assert_eq!(decoded, raw);
        assert!(String::from_utf8(raw.to_vec()).is_err(), "test bytes must be invalid UTF-8");
    }
}
