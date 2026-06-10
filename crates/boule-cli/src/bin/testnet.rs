use boule_node::testnet::cli;

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "warn,boule_node::testnet=info".into());
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
