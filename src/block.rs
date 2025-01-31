use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

use anyhow::Result;
use hex;
use serde;
use serde_json;
use sha3::{Digest, Sha3_256};
use tokio;

use crate::GlobalArgs;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BlockContent {
    // Those are base64 encoded
    pub encrypted: Vec<String>,
    pub plain: Option<String>,
    pub signature: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub content: BlockContent,
    pub parents: BTreeSet<String>,
    pub timestamp: u64,
}

pub async fn read_block_file(global_args: &GlobalArgs, hash: &str) -> Result<String> {
    let file_path = global_args.db_path.join("blocks").join(hash);
    let block_file_content = tokio::fs::read_to_string(file_path).await?;
    Ok(block_file_content)
}

pub async fn read_block(global_args: &GlobalArgs, hash: &str) -> Result<Block> {
    let block_file_content = read_block_file(global_args, hash).await?;

    let block = serde_json::from_str::<Block>(&block_file_content)?;
    Ok(block)
}

pub fn block_verify<'a>(
    global_args: &'a GlobalArgs,
    hash: &'a str,
) -> Pin<Box<impl Future<Output = Result<bool>> + use<'a>>> {
    Box::pin(async move {
        let block_file_content = read_block_file(global_args, hash).await?;
        let mut hasher = Sha3_256::new();
        hasher.update(block_file_content.as_bytes());
        let hash_computed = hasher.finalize();
        let hash_computed_hex = hex::encode(hash_computed.as_slice());

        let block = serde_json::from_str::<Block>(&block_file_content)?;
        for parent in block.parents {
            if !block_verify(global_args, &parent).await? {
                return Ok(false);
            }
        }

        Ok(hash_computed_hex == hash)
    })
}

pub async fn write_block(global_args: &GlobalArgs, block: &Block) -> Result<String> {
    let file_content = serde_json::to_string(&block)?;

    let mut hasher = Sha3_256::new();
    hasher.update(file_content.as_bytes());
    let hash_computed = hasher.finalize();
    let hash_computed_hex = hex::encode(hash_computed.as_slice());

    let file_path = global_args.db_path.join("blocks").join(&hash_computed_hex);
    tokio::fs::write(file_path, file_content).await?;
    Ok(hash_computed_hex)
}
