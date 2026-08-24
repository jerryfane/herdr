use serde::{Deserialize, Serialize};

/// Parameters for `fs.list_dir` — list a single directory's entries, for an app
/// folder picker. `path` is absolute; a leading `~` is expanded and `None`
/// defaults to `$HOME`. Read-only; never writes or traverses recursively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct FsListDirParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}
