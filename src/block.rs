use std::collections::BTreeSet;

use anyhow::Result;
use hex;
use serde;
use serde_json;
use sha3;
use tokio;

use crate::GlobalArgs;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub content: String,
    pub parents: BTreeSet<String>,
}

pub async fn read_block(global_args: &GlobalArgs, hash: &str) -> Result<Block> {
    let file_path = global_args.db_path.join("blocks").join(hash);
    let block_file_content = tokio::fs::read_to_string(file_path).await?;

    let block = serde_json::from_str::<Block>(&block_file_content)?;
    Ok(block)
}
