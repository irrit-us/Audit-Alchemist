//! Deterministic context projection; archived outputs are scoped to one run.
use anyhow::{ensure, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    io::Write,
    path::PathBuf,
};

#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum ContextPolicy {
    /// Archive older tool output under pressure; preserve recent turns and skills.
    #[default]
    Prune,
    /// Keep history unchanged and fail when the request exceeds its byte cap.
    Fail,
}
impl ContextPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prune => "prune",
            Self::Fail => "fail",
        }
    }
}

/// Count the actual JSON wire representation without allocating a second copy.
pub fn serialized_bytes(value: &impl Serialize) -> Result<usize> {
    struct Counter(usize);
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.0)
}

const ARCHIVE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
pub struct ResultArchive {
    directory: Option<tempfile::TempDir>,
    bytes: usize,
    files: usize,
    reused_outputs: usize,
    saved: HashMap<u64, Vec<SavedResult>>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ArchiveStats {
    pub stored_bytes: usize,
    pub distinct_files: usize,
    pub reused_outputs: usize,
}

struct SavedResult {
    path: PathBuf,
    model_path: String,
}
impl ResultArchive {
    /// Archive only observed result bytes, never regenerate or replay a tool.
    pub fn save(&mut self, content: &str) -> Result<Option<String>> {
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        let key = hasher.finish();
        if let Some(entries) = self.saved.get(&key) {
            for entry in entries {
                // The hash is only an index. Compare actual bytes so a collision
                // or a host-modified archive cannot substitute different output.
                match std::fs::read(&entry.path) {
                    Ok(bytes) if bytes == content.as_bytes() => {
                        self.reused_outputs += 1;
                        return Ok(Some(entry.model_path.clone()));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        if content.len() > ARCHIVE_BYTES.saturating_sub(self.bytes) || self.files >= 256 {
            return Ok(None);
        }
        if self.directory.is_none() {
            self.directory = Some(
                tempfile::Builder::new()
                    .prefix("audit-context-")
                    .tempdir()?,
            );
        }
        let path = self
            .directory
            .as_ref()
            .unwrap()
            .path()
            .join(format!("result-{}.json", self.files));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&path)?.write_all(content.as_bytes())?;
        self.bytes += content.len();
        self.files += 1;
        // Git Bash accepts drive:/path on Windows. No shell command is generated.
        let model_path = path.to_string_lossy().into_owned();
        let model_path = if cfg!(windows) {
            model_path.replace('\\', "/")
        } else {
            model_path
        };
        self.saved.entry(key).or_default().push(SavedResult {
            path,
            model_path: model_path.clone(),
        });
        Ok(Some(model_path))
    }

    pub fn stats(&self) -> ArchiveStats {
        ArchiveStats {
            stored_bytes: self.bytes,
            distinct_files: self.files,
            reused_outputs: self.reused_outputs,
        }
    }
}

/// Keep JSON valid and retain execution status even when large content is cut.
/// The budget includes escaping, metadata, and the truncation notice itself.
pub fn project_result(original: &str, limit: usize, archive: Option<&str>) -> Result<String> {
    ensure!(
        limit >= 1024,
        "tool result budget must be at least 1024 bytes"
    );
    if original.len() <= limit {
        return Ok(original.to_owned());
    }
    let source: Value = serde_json::from_str(original)?;
    let mut projection = json!({"truncated":true,"original_bytes":original.len(),"preview":""});
    if let Some(path) = archive {
        projection["context_archive"] = json!({"path":path,"note":"Read saved output with Bash; do not repeat side effects to recover it."});
    } else {
        projection["notice"] =
            json!("Output shortened; omitted bytes are not retained by this projection.");
    }
    if let Some(error) = source.get("error") {
        let mut message = error.as_str().unwrap_or("tool reported an error");
        message = utf8_head(message, 128);
        while serialized_bytes(&message)? > 160 {
            message = utf8_head(message, message.len() / 2);
        }
        projection["error"] = json!(message);
    }
    for key in [
        "exit_code",
        "timed_out",
        "remaining_tool_calls",
        "isError",
        "path",
        "bytes_written",
        "replacements",
        "total_lines",
        "next_offset",
    ] {
        if let Some(value) = source.get(key) {
            if serialized_bytes(value)? <= 128 {
                projection[key] = value.clone();
                if serialized_bytes(&projection)? > limit - 64 {
                    projection.as_object_mut().unwrap().remove(key);
                }
            }
        }
    }
    // Only preview changes during the search. Count fixed metadata once, then
    // measure the escaped preview string for each candidate width.
    let fixed_bytes = serialized_bytes(&projection)? - 2; // empty preview is `""`
    let mut low = 0;
    let mut high = limit;
    while low < high {
        let middle = (low + high).div_ceil(2);
        let candidate = preview(original, middle);
        if fixed_bytes + serialized_bytes(&candidate)? <= limit {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    projection["preview"] = json!(preview(original, low));
    let result = serde_json::to_string(&projection)?;
    ensure!(
        result.len() <= limit,
        "tool result metadata exceeds output budget"
    );
    Ok(result)
}
fn utf8_head(text: &str, mut bytes: usize) -> &str {
    bytes = bytes.min(text.len());
    while !text.is_char_boundary(bytes) {
        bytes -= 1;
    }
    &text[..bytes]
}
fn preview(text: &str, bytes: usize) -> String {
    let head = utf8_head(text, bytes / 2);
    let mut tail = text.len().saturating_sub(bytes / 2);
    while !text.is_char_boundary(tail) {
        tail += 1;
    }
    format!("{head}\n[... omitted ...]\n{}", &text[tail..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_is_valid_json_and_counts_escaping_and_metadata() {
        let original = json!({"stdout":format!("HEAD{}TAIL", "雪\"\\\n\u{0000}".repeat(5000)),"error":"failure","exit_code":7,"timed_out":true,"remaining_tool_calls":4}).to_string();
        for limit in [1024, 4096, 32768] {
            let text = project_result(&original, limit, Some("/tmp/saved.json")).unwrap();
            assert!(text.len() <= limit);
            assert_eq!(
                serialized_bytes(&serde_json::from_str::<Value>(&text).unwrap()).unwrap(),
                text.len()
            );
            let value: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(value["error"], "failure");
            assert_eq!(value["exit_code"], 7);
            assert_eq!(value["remaining_tool_calls"], 4);
            assert_eq!(value["truncated"], true);
            assert_eq!(value["context_archive"]["path"], "/tmp/saved.json");
        }
        assert_eq!(
            project_result("{\"ok\":true}", 1024, None).unwrap(),
            "{\"ok\":true}"
        );
        let mut crowded = json!({"stdout":"x".repeat(5000),"error":"\u{0000}".repeat(128),"exit_code":7,"timed_out":true});
        for key in [
            "path",
            "bytes_written",
            "replacements",
            "total_lines",
            "next_offset",
        ] {
            crowded[key] = json!("x".repeat(120));
        }
        let projected =
            project_result(&crowded.to_string(), 1024, Some("/tmp/result.json")).unwrap();
        assert!(projected.len() <= 1024);
        let value: Value = serde_json::from_str(&projected).unwrap();
        assert_eq!(value["exit_code"], 7);
        assert_eq!(value["timed_out"], true);
        assert!(value["error"].is_string());
    }

    #[test]
    fn archived_bytes_are_exact_bounded_and_removed_on_drop() {
        let mut archive = ResultArchive::default();
        let original = "{\"stdout\":\"observed 雪\"}";
        let path = archive.save(original).unwrap().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert!(archive.save(&"x".repeat(ARCHIVE_BYTES)).unwrap().is_none());
        for index in 1..256 {
            assert!(archive
                .save(&format!("{{\"index\":{index}}}"))
                .unwrap()
                .is_some());
        }
        assert!(archive.save("{}").unwrap().is_none());
        drop(archive);
        assert!(!std::path::Path::new(&path).exists());
    }

    #[test]
    fn duplicate_outputs_reuse_exact_archive_without_spending_quota() {
        let mut archive = ResultArchive::default();
        let output = "repeated observed output".repeat(4096);
        let first = archive.save(&output).unwrap().unwrap();
        for _ in 0..300 {
            assert_eq!(archive.save(&output).unwrap().unwrap(), first);
        }
        assert_eq!(archive.files, 1);
        assert_eq!(archive.bytes, output.len());
        assert_eq!(archive.stats().reused_outputs, 300);
        std::fs::write(&first, "modified outside the archive").unwrap();
        let second = archive.save(&output).unwrap().unwrap();
        assert_ne!(second, first);
        assert_eq!(std::fs::read_to_string(second).unwrap(), output);
    }
}
