use axum::{routing::get, Router};
use clap::Parser;
use rustls::ServerConfig;
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio_rustls_acme::caches::DirCache;
use tokio_rustls_acme::AcmeConfig;
use tokio_stream::StreamExt;
use tlsn_verifier::tls::{Verifier, VerifierConfig};
use tls_core::{anchors::RootCertStore, verify::WebPkiVerifier};
pub static CA_CERT_DER: &[u8] = include_bytes!("../root_ca_cert.der");


#[derive(Parser, Debug)]
struct Args {
    /// Domains
    #[clap(short, required = true)]
    domains: Vec<String>,

    /// Contact info
    #[clap(short)]
    email: Vec<String>,

    /// Cache directory
    #[clap(short)]
    cache: Option<PathBuf>,

    /// Use Let's Encrypt production environment
    /// (see https://letsencrypt.org/docs/staging-environment/)
    #[clap(long)]
    prod: bool,

    #[clap(short, long, default_value = "443")]
    port: u16,
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
    let acceptor = state.axum_acceptor(Arc::new(rustls_config));

    tokio::spawn(async move {
        loop {
            match state.next().await.unwrap() {
                Ok(ok) => log::info!("event: {:?}", ok),
                Err(err) => log::error!("error: {:?}", err),
            }
        }
    });

    let app = Router::new().route("/", get(|| async { 

    let mut root_store = RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let verifier_config = VerifierConfig::builder()
        .id("test")
        .cert_verifier(WebPkiVerifier::new(root_store, None))
        .build()
        .unwrap();
    let verifier = Verifier::new(verifier_config);

    }));

    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, args.port));
    axum_server::bind(addr)
        .acceptor(acceptor)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
