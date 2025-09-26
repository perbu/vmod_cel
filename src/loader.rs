use crate::bundle::{RuleBundle, RuleSet, CompiledRule};
use crate::policy_engine::PolicyEngine;
use crate::cel_engine::CelRustEngine;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LoadError {
    #[error("File I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Compilation error in rule '{rule}': {error}")]
    CompilationError { rule: String, error: String },
    #[error("Unsupported file format: {0}")]
    UnsupportedFormat(String),
}

/// Result type for loading operations
pub type LoadResult<T> = Result<T, LoadError>;

/// Bundle loader with CEL compilation support
pub struct BundleLoader {
    /// CEL engine for compilation
    engine: Arc<CelRustEngine>,
}

impl BundleLoader {
    /// Create new bundle loader with default CEL engine
    pub fn new() -> Result<Self, LoadError> {
        let engine = CelRustEngine::new()
            .map_err(|e| LoadError::CompilationError {
                rule: "engine_init".to_string(),
                error: e.to_string()
            })?;

        Ok(Self {
            engine: Arc::new(engine),
        })
    }

    /// Create new bundle loader with specific CEL engine
    pub fn with_engine(engine: Arc<CelRustEngine>) -> Self {
        Self { engine }
    }

    /// Load bundle from file path
    pub fn load_file<P: AsRef<Path>>(&self, path: P) -> LoadResult<Arc<RuleSet>> {
        let path = path.as_ref();
        let content = fs::read_to_string(path)?;
        let format = detect_format(path)?;

        self.load_from_content(&content, format)
    }

    /// Load bundle from string content
    pub fn load_blob(&self, content: &str, format: BundleFormat) -> LoadResult<Arc<RuleSet>> {
        self.load_from_content(content, format)
    }

    /// Load bundle from content with specified format
    fn load_from_content(&self, content: &str, format: BundleFormat) -> LoadResult<Arc<RuleSet>> {
        // Parse bundle
        let bundle = match format {
            BundleFormat::Yaml => RuleBundle::from_yaml(content)
                .map_err(LoadError::ParseError)?,
            BundleFormat::Json => RuleBundle::from_json(content)
                .map_err(LoadError::ParseError)?,
        };

        // Validate bundle structure
        bundle.validate()
            .map_err(LoadError::ValidationError)?;

        // Compile rules (placeholder for Phase 3)
        self.compile_bundle(bundle)
    }

    /// Load bundle in background thread
    pub fn load_file_async<P: AsRef<Path> + Send + 'static>(
        &self,
        path: P,
        callback: Box<dyn FnOnce(LoadResult<Arc<RuleSet>>) + Send + 'static>
    ) {
        let path_buf = path.as_ref().to_path_buf();

        thread::spawn(move || {
            let loader = BundleLoader::new().expect("Failed to create loader");
            let result = loader.load_file(path_buf);
            callback(result);
        });
    }

    /// Load bundle from content in background thread
    pub fn load_blob_async(
        &self,
        content: String,
        format: BundleFormat,
        callback: Box<dyn FnOnce(LoadResult<Arc<RuleSet>>) + Send + 'static>
    ) {
        thread::spawn(move || {
            let loader = BundleLoader::new().expect("Failed to create loader");
            let result = loader.load_blob(&content, format);
            callback(result);
        });
    }

    /// Compile bundle into rule set using real CEL compilation
    fn compile_bundle(&self, bundle: RuleBundle) -> LoadResult<Arc<RuleSet>> {
        let mut rule_set = RuleSet::new();
        rule_set.metadata = bundle.metadata.clone();

        for rule in bundle.rules {
            // Skip disabled rules
            if !rule.enabled {
                continue;
            }

            // Compile CEL expression
            let start_time = Instant::now();
            let program = self.engine.compile(&rule.name, &rule.expr)
                .map_err(|e| LoadError::CompilationError {
                    rule: rule.name.clone(),
                    error: e.to_string(),
                })?;

            let compile_time_us = start_time.elapsed().as_micros() as u64;

            // Estimate cost
            let estimated_cost = self.engine.estimate_cost(&rule.expr)
                .map_err(|e| LoadError::CompilationError {
                    rule: rule.name.clone(),
                    error: format!("Cost estimation failed: {}", e),
                })?;

            let compiled_rule = CompiledRule {
                rule: rule.clone(),
                program,
                estimated_cost,
                compile_time_us,
            };

            rule_set.programs.insert(rule.name.clone(), compiled_rule);
        }

        Ok(Arc::new(rule_set))
    }
}

impl Default for BundleLoader {
    fn default() -> Self {
        Self::new().expect("Failed to create default BundleLoader")
    }
}

/// Supported bundle formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleFormat {
    Yaml,
    Json,
}

/// Detect bundle format from file extension
fn detect_format<P: AsRef<Path>>(path: P) -> LoadResult<BundleFormat> {
    let path = path.as_ref();

    match path.extension().and_then(|ext| ext.to_str()) {
        Some("yaml") | Some("yml") => Ok(BundleFormat::Yaml),
        Some("json") => Ok(BundleFormat::Json),
        Some(ext) => Err(LoadError::UnsupportedFormat(ext.to_string())),
        None => Err(LoadError::UnsupportedFormat("no extension".to_string())),
    }
}

/// Atomic rule set swapper for hot reloading
pub struct RuleSetSwapper {
    current: Arc<std::sync::RwLock<Arc<RuleSet>>>,
}

impl RuleSetSwapper {
    /// Create new swapper with empty rule set
    pub fn new() -> Self {
        Self {
            current: Arc::new(std::sync::RwLock::new(Arc::new(RuleSet::new()))),
        }
    }

    /// Get current rule set
    pub fn get(&self) -> Arc<RuleSet> {
        self.current.read().unwrap().clone()
    }

    /// Atomically swap rule set
    pub fn swap(&self, new_rules: Arc<RuleSet>) -> Arc<RuleSet> {
        let mut current = self.current.write().unwrap();
        let old = current.clone();
        *current = new_rules;
        old
    }

    /// Try to swap rule set, keeping old on failure
    pub fn try_swap(&self, new_rules: LoadResult<Arc<RuleSet>>) -> LoadResult<Arc<RuleSet>> {
        match new_rules {
            Ok(rules) => Ok(self.swap(rules)),
            Err(e) => Err(e),
        }
    }

    /// Load and swap from file, keeping old rules on failure
    pub fn load_and_swap<P: AsRef<Path>>(&self, path: P) -> LoadResult<Arc<RuleSet>> {
        let loader = BundleLoader::new()?;
        let new_rules = loader.load_file(path)?;
        Ok(self.swap(new_rules))
    }

    /// Load and swap from content, keeping old rules on failure
    pub fn load_blob_and_swap(&self, content: &str, format: BundleFormat) -> LoadResult<Arc<RuleSet>> {
        let loader = BundleLoader::new()?;
        let new_rules = loader.load_blob(content, format)?;
        Ok(self.swap(new_rules))
    }
}

impl Default for RuleSetSwapper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_format_detection() {
        assert_eq!(detect_format("rules.yaml").unwrap(), BundleFormat::Yaml);
        assert_eq!(detect_format("rules.yml").unwrap(), BundleFormat::Yaml);
        assert_eq!(detect_format("rules.json").unwrap(), BundleFormat::Json);
        assert!(detect_format("rules.txt").is_err());
    }

    #[test]
    fn test_load_yaml_bundle() {
        let yaml_content = r#"
version: 1
rules:
  - name: test_rule
    expr: request.method == "GET"
    enabled: true
"#;

        let loader = BundleLoader::new().expect("Failed to create loader");
        let result = loader.load_blob(yaml_content, BundleFormat::Yaml);
        assert!(result.is_ok());

        let rule_set = result.unwrap();
        assert_eq!(rule_set.rule_count(), 1);
        assert!(rule_set.get_rule("test_rule").is_some());
    }

    #[test]
    fn test_load_json_bundle() {
        let json_content = r#"{
  "version": 1,
  "rules": [
    {
      "name": "json_rule",
      "expr": "true",
      "enabled": true
    }
  ]
}"#;

        let loader = BundleLoader::new().expect("Failed to create loader");
        let result = loader.load_blob(json_content, BundleFormat::Json);
        assert!(result.is_ok());

        let rule_set = result.unwrap();
        assert_eq!(rule_set.rule_count(), 1);
    }

    #[test]
    fn test_load_file() -> Result<(), Box<dyn std::error::Error>> {
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(br#"
version: 1
rules:
  - name: file_rule
    expr: request.path.startsWith("/api")
"#)?;

        // Rename to .yaml extension for format detection
        let yaml_path = temp_file.path().with_extension("yaml");
        std::fs::copy(temp_file.path(), &yaml_path)?;

        let loader = BundleLoader::new().expect("Failed to create loader");
        let result = loader.load_file(&yaml_path);

        std::fs::remove_file(yaml_path)?;

        assert!(result.is_ok());
        Ok(())
    }

    #[test]
    fn test_rule_set_swapper() {
        let swapper = RuleSetSwapper::new();

        // Initial empty state
        let initial = swapper.get();
        assert_eq!(initial.rule_count(), 0);

        // Create a new rule set
        let mut new_rules = RuleSet::new();
        new_rules.programs.insert(
            "test".to_string(),
            CompiledRule {
                rule: crate::bundle::Rule {
                    name: "test".to_string(),
                    expr: "true".to_string(),
                    enabled: true,
                    description: None,
                    tags: vec![],
                },
                program: ::cel::Program::compile("true").expect("Failed to compile test program"),
                estimated_cost: 10,
                compile_time_us: 100,
            }
        );

        // Swap and verify
        let old = swapper.swap(Arc::new(new_rules));
        assert_eq!(old.rule_count(), 0);

        let current = swapper.get();
        assert_eq!(current.rule_count(), 1);
    }

    #[test]
    fn test_disabled_rules_skipped() {
        let yaml_content = r#"
version: 1
rules:
  - name: enabled_rule
    expr: "true"
    enabled: true
  - name: disabled_rule
    expr: "false"
    enabled: false
"#;

        let loader = BundleLoader::new().expect("Failed to create loader");
        let result = loader.load_blob(yaml_content, BundleFormat::Yaml);
        assert!(result.is_ok());

        let rule_set = result.unwrap();
        assert_eq!(rule_set.rule_count(), 1); // Only enabled rule loaded
        assert!(rule_set.get_rule("enabled_rule").is_some());
        assert!(rule_set.get_rule("disabled_rule").is_none());
    }

    #[test]
    fn test_validation_errors() {
        // Test empty rules
        let empty_yaml = r#"
version: 1
rules: []
"#;
        let loader = BundleLoader::new().expect("Failed to create loader");
        let result = loader.load_blob(empty_yaml, BundleFormat::Yaml);
        assert!(matches!(result, Err(LoadError::ValidationError(_))));

        // Test duplicate rule names
        let duplicate_yaml = r#"
version: 1
rules:
  - name: duplicate
    expr: "true"
  - name: duplicate
    expr: "false"
"#;
        let result = loader.load_blob(duplicate_yaml, BundleFormat::Yaml);
        assert!(matches!(result, Err(LoadError::ValidationError(_))));
    }
}