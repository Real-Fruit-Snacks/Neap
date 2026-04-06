use std::sync::Arc;

use log::info;
use russh::server::{Config, Server as _};

use crate::error::{NeapError, Result};
use crate::server::{build_config, generate_host_key, NeapServer};
use crate::Params;

/// Main entry point for the transport layer.
pub async fn run(params: &Params) -> Result<()> {
    let host_key = generate_host_key()?;
    let ssh_config = build_config(host_key);

    let server = NeapServer {
        shell: params.shell.clone(),
        no_shell: params.no_shell,
    };

    if params.listen || params.lhost.is_empty() {
        run_bind(params, ssh_config, server).await
    } else {
        run_reverse(params, ssh_config, server).await
    }
}

/// Bind mode: listen on a local port and serve SSH connections.
async fn run_bind(params: &Params, config: Arc<Config>, mut server: NeapServer) -> Result<()> {
    let addr = format!("0.0.0.0:{}", params.lport);
    info!("Starting ssh server on :{}", params.lport);
    info!("Success: listening on {}", addr);

    server
        .run_on_address(config, &addr as &str)
        .await
        .map_err(NeapError::Io)
}

/// Reverse mode: connect back to a remote host (stub).
async fn run_reverse(
    _params: &Params,
    _config: Arc<Config>,
    _server: NeapServer,
) -> Result<()> {
    Err(NeapError::Config("Reverse mode not yet implemented".into()))
}
