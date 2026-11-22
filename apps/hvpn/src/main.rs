use clap::Parser;
use hello_cli::Cli;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = cli.run().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
