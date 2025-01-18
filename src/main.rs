mod block;
mod refs;

use std::path::PathBuf;

use anyhow::Result;
use clap;
use clap::Parser;

#[derive(Parser)]
#[command(about, long_about = None)]
struct Args {
    #[command(flatten)]
    global_args: GlobalArgs,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser)]
struct GlobalArgs {
    #[arg(short = 'p', long = "db-path", default_value = "./db/")]
    db_path: PathBuf,
}

#[derive(clap::Subcommand)]
enum Commands {
    Select { hash: String },
    GetBlock { refe: String },
    Tag { name: String, refe: String },
}

async fn ensure_db_dirs(global_args: &GlobalArgs) -> Result<()> {
    tokio::fs::create_dir_all(global_args.db_path.join("blocks")).await?;
    tokio::fs::create_dir_all(global_args.db_path.join("refs")).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Hello, world!");

    let args = Args::parse();

    ensure_db_dirs(&args.global_args).await?;

    match args.command {
        Commands::Select { hash } => {}
        Commands::GetBlock { refe } => {
            let hash = refs::Ref::from_str(&args.global_args, &refe).await?;
            println!("Block with hash {}", hash);
            if block::block_verify(&args.global_args, &hash).await? {
                println!("Verification succesful");
            } else {
                eprintln!("Verification failed!");
            }
        }
        Commands::Tag { name, refe } => {
            let hash = refs::Ref::from_str(&args.global_args, &refe).await?;
            let tag = refs::Tag { name };
            tag.write(&args.global_args, &hash).await?;
        }
    }

    Ok(())
}
