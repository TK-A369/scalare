use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

use anyhow::Result;
use hex;
use rsa;
use serde;
use serde_json;
use sha3::{Digest, Sha3_256};
use tokio;

use crate::GlobalArgs;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BlockContent {
    encrypted: Vec<Vec<u8>>,
    plain: Option<Vec<u8>>,
    signatures: Vec<Vec<u8>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub content: BlockContent,
    pub parents: BTreeSet<String>,
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
    Box::pin(async {
        let block_file_content = read_block_file(global_args, hash).await?;
        let mut hasher = Sha3_256::new();
        hasher.update(block_file_content.as_bytes());
        let hash_computed = hasher.finalize();
        let hash_computed = hash_computed.as_slice();

        let block = serde_json::from_str::<Block>(&block_file_content)?;
        for parent in block.parents {
            if !block_verify(global_args, hash).await? {
                return Ok(false);
            }
        }

        Ok(hash_computed == hash.as_bytes())
    })
}
