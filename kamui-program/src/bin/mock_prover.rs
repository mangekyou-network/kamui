use {
    kamui_program::mock_prover::MockProver,
    clap::Parser,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Solana RPC URL
    #[arg(short, long, default_value = "http://localhost:8899")]
    url: String,

    /// VRF Coordinator program ID
    #[arg(short, long)]
    keypair: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut mock_prover = MockProver::new().await;
    
    println!("Mock prover initialized with URL: {}", args.url);
    println!("Using keypair: {}", args.keypair);
    
    Ok(())
} 