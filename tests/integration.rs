// ---------------------------------------------------------------------------
// Existing integration tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_config_defaults() {
    assert_eq!(neap::config::PASSWORD, "letmeinbrudipls");
    assert_eq!(neap::config::LUSER, "svc");
    assert_eq!(neap::config::LPORT, "31337");
    assert_eq!(neap::config::BPORT, "0");
    assert_eq!(neap::config::DEFAULT_SHELL, "/bin/bash");
    assert_eq!(neap::config::SSH_VERSION, "OpenSSH_8.9");
    assert_eq!(neap::config::TLS_SNI, "www.microsoft.com");
}

#[tokio::test]
async fn test_extra_info_serialization() {
    use neap::info::ExtraInfo;

    let info = ExtraInfo {
        current_user: "root".to_string(),
        hostname: "target-01".to_string(),
        listening_address: "127.0.0.1:31337".to_string(),
    };

    let bytes = info.to_ssh_bytes();
    let decoded = ExtraInfo::from_ssh_bytes(&bytes).unwrap();

    assert_eq!(decoded.current_user, "root");
    assert_eq!(decoded.hostname, "target-01");
    assert_eq!(decoded.listening_address, "127.0.0.1:31337");
}

#[tokio::test]
async fn test_free_port_binding() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    assert!(port > 0);
}

// ---------------------------------------------------------------------------
// 1. Config validation tests
// ---------------------------------------------------------------------------

#[test]
fn test_config_version_not_empty() {
    assert!(!neap::config::VERSION.is_empty());
}

#[test]
fn test_config_ssh_version_format() {
    assert!(neap::config::SSH_VERSION.starts_with("OpenSSH"));
}

#[test]
fn test_config_lport_is_valid_port() {
    let port: u16 = neap::config::LPORT.parse().expect("LPORT should be a valid u16");
    assert!(port > 0);
}

#[test]
fn test_config_bport_is_valid_port() {
    let _port: u16 = neap::config::BPORT.parse().expect("BPORT should be a valid u16");
}

#[test]
fn test_config_tls_sni_not_empty() {
    assert!(!neap::config::TLS_SNI.is_empty());
}

// ---------------------------------------------------------------------------
// 2. Error type tests
// ---------------------------------------------------------------------------

#[test]
fn test_error_display_io() {
    let err = neap::error::NeapError::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "test",
    ));
    let display = format!("{}", err);
    assert!(display.contains("IO error"));
}

#[test]
fn test_error_display_config() {
    let err = neap::error::NeapError::Config("test message".into());
    let display = format!("{}", err);
    assert!(display.contains("test message"));
}

#[test]
fn test_error_display_invalid_port() {
    let err = neap::error::NeapError::InvalidPort("99999".into());
    let display = format!("{}", err);
    assert!(display.contains("99999"));
}

#[test]
fn test_error_from_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
    let neap_err: neap::error::NeapError = io_err.into();
    assert!(matches!(neap_err, neap::error::NeapError::Io(_)));
}

// ---------------------------------------------------------------------------
// 3. ExtraInfo edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_extra_info_unicode() {
    use neap::info::ExtraInfo;
    let info = ExtraInfo {
        current_user: "用户".to_string(),
        hostname: "主机".to_string(),
        listening_address: "127.0.0.1:8080".to_string(),
    };
    let bytes = info.to_ssh_bytes();
    let decoded = ExtraInfo::from_ssh_bytes(&bytes).unwrap();
    assert_eq!(decoded.current_user, "用户");
    assert_eq!(decoded.hostname, "主机");
}

#[test]
fn test_extra_info_long_strings() {
    use neap::info::ExtraInfo;
    let long_str = "a".repeat(10000);
    let info = ExtraInfo {
        current_user: long_str.clone(),
        hostname: long_str.clone(),
        listening_address: long_str.clone(),
    };
    let bytes = info.to_ssh_bytes();
    let decoded = ExtraInfo::from_ssh_bytes(&bytes).unwrap();
    assert_eq!(decoded.current_user.len(), 10000);
}

// ---------------------------------------------------------------------------
// 4. CLI parsing tests
// ---------------------------------------------------------------------------

#[test]
fn test_binary_help_flag() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_neap"))
        .arg("--help")
        .output()
        .expect("failed to run neap --help");
    // --help exits with code 0 in clap
    assert!(output.status.success() || output.status.code() == Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("penetration testing") || stdout.contains("neap"));
}

#[test]
fn test_binary_version_flag() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_neap"))
        .arg("--version")
        .output()
        .expect("failed to run neap --version");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("neap") || stdout.contains("1.0.0"));
}
