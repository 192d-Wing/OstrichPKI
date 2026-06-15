//! Live mTLS e2e: the custom TLS `Accept` in `ostrich_common::tls::serve`
//! surfaces the verified client certificate to handlers as a `PeerCertificate`
//! request extension.
//!
//! Generates a CA, a server cert (SAN IP:127.0.0.1), and a client cert with
//! openssl, serves a tiny router over TLS that REQUIRES a client certificate,
//! and connects with a reqwest client presenting that cert. The handler reads
//! the peer certificate and echoes its subject, which must equal the client
//! cert's subject — proving the verified client identity reaches the app layer.
//!
//! Gated on the `openssl` binary; skips otherwise.

use std::process::Command;

use axum::{routing::get, Extension, Router};
use ostrich_common::tls::{serve, PeerCertificate, TlsSettings};

fn openssl(args: &[&str]) {
    let out = Command::new("openssl")
        .args(args)
        .output()
        .expect("run openssl");
    assert!(
        out.status.success(),
        "openssl {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

async fn whoami(Extension(peer): Extension<PeerCertificate>) -> String {
    match peer.0 {
        Some(der) => match ostrich_x509::parser::parse_subject_dn(&der) {
            Ok(dn) => dn.to_string_rfc4514(),
            Err(e) => format!("parse-error: {e}"),
        },
        None => "no-client-cert".to_string(),
    }
}

#[tokio::test]
async fn mtls_client_cert_reaches_handler() {
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("mtls_peercert_e2e: openssl not found; skipping");
        return;
    }

    let dir = std::env::temp_dir().join(format!("ostrich-mtls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = |f: &str| dir.join(f).to_str().unwrap().to_string();

    // CA (EC P-256, self-signed).
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-days",
        "1",
        "-nodes",
        "-keyout",
        &p("ca.key"),
        "-out",
        &p("ca.crt"),
        "-subj",
        "/CN=Test mTLS CA",
    ]);
    // Server key + CSR + cert with SAN IP:127.0.0.1.
    openssl(&[
        "req",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        &p("server.key"),
        "-out",
        &p("server.csr"),
        "-subj",
        "/CN=localhost",
    ]);
    std::fs::write(dir.join("san.ext"), "subjectAltName=IP:127.0.0.1\n").unwrap();
    openssl(&[
        "x509",
        "-req",
        "-in",
        &p("server.csr"),
        "-CA",
        &p("ca.crt"),
        "-CAkey",
        &p("ca.key"),
        "-CAcreateserial",
        "-days",
        "1",
        "-out",
        &p("server.crt"),
        "-extfile",
        &p("san.ext"),
    ]);
    // Client key + CSR + cert (CN=client.test).
    openssl(&[
        "req",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-keyout",
        &p("client.key"),
        "-out",
        &p("client.csr"),
        "-subj",
        "/CN=client.test",
    ]);
    openssl(&[
        "x509",
        "-req",
        "-in",
        &p("client.csr"),
        "-CA",
        &p("ca.crt"),
        "-CAkey",
        &p("ca.key"),
        "-CAcreateserial",
        "-days",
        "1",
        "-out",
        &p("client.crt"),
    ]);

    // Serve over TLS requiring a client cert (client_ca = our CA).
    let tls = TlsSettings::from_options(
        Some(p("server.crt")),
        Some(p("server.key")),
        Some(p("ca.crt")),
    )
    .unwrap()
    .unwrap();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let app = Router::new().route("/whoami", get(whoami));
    tokio::spawn(async move {
        let _ = serve(addr, app, Some(&tls), std::future::pending::<()>()).await;
    });
    // Wait for the listener.
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let ca_pem = std::fs::read(dir.join("ca.crt")).unwrap();
    let mut client_pem = std::fs::read(dir.join("client.crt")).unwrap();
    client_pem.extend_from_slice(&std::fs::read(dir.join("client.key")).unwrap());

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem).unwrap())
        .identity(reqwest::Identity::from_pem(&client_pem).unwrap())
        .build()
        .unwrap();

    let body = client
        .get(format!("https://127.0.0.1:{port}/whoami"))
        .send()
        .await
        .expect("mTLS request")
        .text()
        .await
        .unwrap();

    assert!(
        body.contains("client.test"),
        "the handler must see the verified client certificate subject; got: {body:?}"
    );

    // A client WITHOUT a certificate must be rejected by the TLS handshake
    // (the server's WebPkiClientVerifier requires a client cert).
    let no_cert = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem).unwrap())
        .build()
        .unwrap()
        .get(format!("https://127.0.0.1:{port}/whoami"))
        .send()
        .await;
    assert!(
        no_cert.is_err(),
        "a connection without a client certificate must be rejected"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
