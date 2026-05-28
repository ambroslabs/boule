//! `testnet` — driver binary for the parameterized testnet. The library half
//! ([`boule::testnet`]) is also usable directly from integration
//! tests; this binary is just the CLI shell that wires argv through to
//! it. See `testnet --help`.

use boule::testnet::cli;

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "warn,boule::testnet=info".into());
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match cli::run_with_signal_handling(&args).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }
}
