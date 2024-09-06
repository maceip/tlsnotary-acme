use tlsn_prover::tls::{Prover, ProverConfig};
use tlsn_server_fixture::bind;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tlsn_verifier::tls::{Verifier, VerifierConfig};

use http_body_util::{BodyExt as _, Empty};
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

use clap::Parser;
use rustls::ServerConfig;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio_rustls_acme::caches::DirCache;
use tokio_rustls_acme::{AcmeAcceptor, AcmeConfig};
use tokio_stream::StreamExt;



#[tokio::test]
#[ignore]
async fn notarize() {
    tracing_subscriber::fmt::init();

    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    tokio::join!(prover(socket_0), notary(socket_1));
}

#[instrument(skip(notary_socket))]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(notary_socket: T) {
    let (client_socket, server_socket) = tokio::io::duplex(2 << 16);

    let server_task = tokio::spawn(bind(server_socket.compat()));

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let prover = Prover::new(
        ProverConfig::builder()
            .id("test")
            .server_dns(SERVER_DOMAIN)
            .root_cert_store(root_store)
            .build()
            .unwrap(),
    )
    .setup(notary_socket.compat())
    .await
    .unwrap();

    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    let prover_task = tokio::spawn(prover_fut);

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat()))
            .await
            .unwrap();

    tokio::spawn(connection);

    let request = Request::builder()
        .uri(format!("https://{}/bytes?size=16000", SERVER_DOMAIN))
        .header("Host", SERVER_DOMAIN)
        .header("Connection", "close")
        .method("GET")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = request_sender.send_request(request).await.unwrap();

    assert!(response.status() == StatusCode::OK);

    let payload = response.into_body().collect().await.unwrap().to_bytes();
    println!("{:?}", &String::from_utf8_lossy(&payload));

    let _ = server_task.await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap().start_notarize();

    let sent_tx_len = prover.sent_transcript().data().len();
    let recv_tx_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();

    // Commit to everything
    builder.commit_sent(&(0..sent_tx_len)).unwrap();
    builder.commit_recv(&(0..recv_tx_len)).unwrap();

    prover.finalize().await.unwrap();
}

#[instrument(skip(socket))]
async fn notary<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(socket: T) {
    let verifier = Verifier::new(VerifierConfig::builder().id("test").build().unwrap());
    let signing_key = p256::ecdsa::SigningKey::from_bytes(&[1u8; 32].into()).unwrap();

    _ = verifier
        .notarize::<_, p256::ecdsa::Signature>(socket.compat(), &signing_key)
        .await
        .unwrap();
}


#[tokio::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info).unwrap();
    let args = Args::parse();

    let mut state = AcmeConfig::new(args.domains)
        .contact(args.email.iter().map(|e| format!("mailto:{}", e)))
        .cache_option(args.cache.clone().map(DirCache::new))
        .directory_lets_encrypt(args.prod)
        .state();
    let rustls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(state.resolver());
    let acceptor = state.acceptor();

    tokio::spawn(async move {
        loop {
            match state.next().await.unwrap() {
                Ok(ok) => log::info!("event: {:?}", ok),
                Err(err) => log::error!("error: {:?}", err),
            }
        }
    });

    serve(acceptor, Arc::new(rustls_config), args.port).await;
}

async fn serve(acceptor: AcmeAcceptor, rustls_config: Arc<ServerConfig>, port: u16) {
    let listener = tokio::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, port))
        .await
        .unwrap();
    loop {
        let tcp = listener.accept().await.unwrap().0;
        let rustls_config = rustls_config.clone();
        let accept_future = acceptor.accept(tcp);

        tokio::spawn(async move {
            match accept_future.await.unwrap() {
                None => log::info!("received TLS-ALPN-01 validation request"),
                Some(start_handshake) => {
                    let mut tls = start_handshake.into_stream(rustls_config).await.unwrap();
                    tls.write_all(HELLO).await.unwrap();
                    tls.shutdown().await.unwrap();
                }
            }
        });
    }
}

y
const HELLO: &[u8] = br#"HTTP/1.1 200 OK
Content-Length: 10
Content-Type: text/plain; charset=utf-8

Hello Tls!"#;

