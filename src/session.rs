use log::{error, info};
use russh::server::Handle;
use russh::{ChannelId, CryptoVec};

/// Execute a command string on behalf of an SSH client.
///
/// Parses `command` by splitting on whitespace, spawns the program via
/// `tokio::process::Command`, and streams stdout/stderr back to the
/// channel.  Sends an exit-status message and closes the channel when
/// the process finishes (or on error).
pub async fn exec_command(command: String, channel_id: ChannelId, handle: Handle) {
    info!("Executing command: {}", command);

    let argv: Vec<&str> = command.split_whitespace().collect();
    if argv.is_empty() {
        let msg = b"neap: empty command\n";
        let _ = handle
            .extended_data(channel_id, 1, CryptoVec::from_slice(msg))
            .await;
        let _ = handle.exit_status_request(channel_id, 255).await;
        let _ = handle.eof(channel_id).await;
        let _ = handle.close(channel_id).await;
        return;
    }

    let program = argv[0];
    let args = &argv[1..];

    let result = tokio::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null())
        .spawn();

    let child = match result {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("neap: failed to spawn '{}': {}\n", program, e);
            error!("{}", msg.trim());
            let _ = handle
                .extended_data(channel_id, 1, CryptoVec::from_slice(msg.as_bytes()))
                .await;
            let _ = handle.exit_status_request(channel_id, 255).await;
            let _ = handle.eof(channel_id).await;
            let _ = handle.close(channel_id).await;
            return;
        }
    };

    match child.wait_with_output().await {
        Ok(output) => {
            // Send stdout
            if !output.stdout.is_empty() {
                let _ = handle
                    .data(channel_id, CryptoVec::from_slice(&output.stdout))
                    .await;
            }
            // Send stderr
            if !output.stderr.is_empty() {
                let _ = handle
                    .extended_data(channel_id, 1, CryptoVec::from_slice(&output.stderr))
                    .await;
            }
            // Send exit status
            let code = output.status.code().unwrap_or(255) as u32;
            let _ = handle.exit_status_request(channel_id, code).await;
        }
        Err(e) => {
            let msg = format!("neap: error waiting for '{}': {}\n", program, e);
            error!("{}", msg.trim());
            let _ = handle
                .extended_data(channel_id, 1, CryptoVec::from_slice(msg.as_bytes()))
                .await;
            let _ = handle.exit_status_request(channel_id, 255).await;
        }
    }

    let _ = handle.eof(channel_id).await;
    let _ = handle.close(channel_id).await;
}
