use anyhow::Result;
use serde;
use tokio;

use crate::GlobalArgs;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Tag {
    pub name: String,
}

impl Tag {
    pub async fn resolve(&self, global_args: &GlobalArgs) -> Result<String> {
        let file_path = global_args.db_path.join("refs").join(&self.name);
        let content = tokio::fs::read_to_string(file_path).await?;
        Ok(content)
    }

    pub async fn write(&self, global_args: &GlobalArgs, hash: &str) -> Result<()> {
        let file_path = global_args.db_path.join("refs").join(&self.name);
        tokio::fs::write(file_path, hash).await?;
        Ok(())
    }
}

pub enum Ref {
    Tag(Tag),
    Hash(String),
}

impl Ref {
    pub async fn from_str(global_args: &GlobalArgs, s: &str) -> Result<String> {
        if let Ok(hash) = (Tag { name: s.into() }.resolve(global_args).await) {
            Ok(hash)
        } else {
            Ok(s.into())
        }
    }
}
