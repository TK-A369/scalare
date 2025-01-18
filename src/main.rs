mod block;
mod refs;

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::Result;
use base64;
use base64::Engine;
use clap;
use clap::Parser;
use rand;

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
    Select {
        hash: String,
    },
    GetBlock {
        refe: String,
    },
    Tag {
        name: String,
        refe: String,
    },
    Commit {
        #[arg(short = 'P', long = "parent")]
        parents: Vec<String>,
        #[arg(short = 'l', long = "plain")]
        plain: bool,
        #[arg(short = 'r', long = "recipient")]
        recipient: Vec<String>,
        #[arg(short = 's', long = "sign")]
        sign: Option<String>,
        file: String,
    },
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

                let block = block::read_block(&args.global_args, &hash).await?;

                if let Some(plain) = block.content.plain {
                    println!("It contains plaintext data");
                } else {
                    println!("It doesn't contain plaintext data");
                }
                if block.content.encrypted.len() == 0 {
                    println!("It doesn't contain encrypted data");
                }
                for enc in block.content.encrypted {
                    // TODO: print public key of rec
                }
            } else {
                eprintln!("Verification failed!");
            }
        }
        Commands::Tag { name, refe } => {
            let hash = refs::Ref::from_str(&args.global_args, &refe).await?;
            let tag = refs::Tag { name };
            tag.write(&args.global_args, &hash).await?;
        }
        Commands::Commit {
            parents,
            plain,
            file,
            recipient,
            sign,
        } => {
            let file_content = tokio::fs::read(file).await?;

            let mut encrypted = vec![];
            for rec in recipient {
                let public_key_content = tokio::fs::read_to_string(&rec).await?;
                let public_key =
                    <rsa::RsaPublicKey as rsa::pkcs1::DecodeRsaPublicKey>::from_pkcs1_pem(
                        &public_key_content,
                    )?;

                let encrypted_msg = public_key.encrypt(
                    &mut rand::thread_rng(),
                    rsa::Pkcs1v15Encrypt,
                    &file_content,
                )?;
                encrypted
                    .push(base64::engine::general_purpose::STANDARD_NO_PAD.encode(encrypted_msg));
            }

            let content = block::BlockContent {
                encrypted,
                plain: if plain {
                    Some(base64::engine::general_purpose::STANDARD_NO_PAD.encode(file_content))
                } else {
                    None
                },
                signature: None,
            };
            let block = block::Block {
                content,
                parents: BTreeSet::from_iter(parents.iter().map(|x| String::from(x))),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };

            let hash = block::write_block(&args.global_args, &block).await?;
            println!("Created new block {}", hash);
        }
    }

    Ok(())
}
