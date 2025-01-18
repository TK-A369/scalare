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
    Extract {
        #[arg(short = 'k', long = "private-key")]
        private_key: Option<String>,
        #[arg(short = 'v', long = "verify")]
        verify_key: Option<String>,
        #[arg(short = 'o', long = "output")]
        output: Option<String>,
        refe: String,
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

                let this_block = block::read_block(&args.global_args, &hash).await?;

                if let Some(plain) = this_block.content.plain {
                    println!("It contains plaintext data");
                } else {
                    println!("It doesn't contain plaintext data");
                }
                if this_block.content.encrypted.len() == 0 {
                    println!("It doesn't contain encrypted data");
                }
                for enc in this_block.content.encrypted {
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

                let mut encrypted_msg: Vec<u8> = Vec::new();
                let chunk_size =
                    <rsa::RsaPublicKey as rsa::traits::PublicKeyParts>::size(&public_key) - 11;
                let mut curr_offset: usize = 0;
                let mut thread_rng = rand::thread_rng();
                while curr_offset < file_content.len() {
                    let mut chunk = public_key.encrypt(
                        &mut thread_rng,
                        rsa::Pkcs1v15Encrypt,
                        &file_content
                            [curr_offset..((curr_offset + chunk_size).min(file_content.len()))],
                    )?;
                    encrypted_msg.append(&mut chunk);
                    curr_offset += chunk_size;
                }
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
        Commands::Extract {
            private_key,
            verify_key,
            output,
            refe,
        } => {
            let hash = refs::Ref::from_str(&args.global_args, &refe).await?;
            if block::block_verify(&args.global_args, &hash).await? {
                let this_block = block::read_block(&args.global_args, &hash).await?;

                let msg = if let Some(private_key) = private_key {
                    let private_key_content = tokio::fs::read_to_string(&private_key).await?;
                    let private_key =
                        <rsa::RsaPrivateKey as rsa::pkcs1::DecodeRsaPrivateKey>::from_pkcs1_pem(
                            &private_key_content,
                        )?;
                    let msg_encrypted_base64 = &this_block.content.encrypted[0];
                    let msg_encrypted = base64::engine::general_purpose::STANDARD_NO_PAD
                        .decode(msg_encrypted_base64)?;
                    private_key.decrypt(rsa::Pkcs1v15Encrypt, &msg_encrypted)?
                } else {
                    // Read plaintext
                    let msg_base64 = this_block
                        .content
                        .plain
                        .ok_or("Block doesn't contain plaintext message")
                        .expect("Block doesn't contain plaintext message");
                    base64::engine::general_purpose::STANDARD_NO_PAD.decode(msg_base64)?
                };

                if let Some(output) = output {
                    // TODO
                } else {
                    println!("{}", String::from_utf8(msg)?);
                }
            } else {
                eprintln!("Verification failed!");
            }
        }
    }

    Ok(())
}
