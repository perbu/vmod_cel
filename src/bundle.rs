use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Version 1 rule bundle format
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleBundle {
    /// Schema version for future compatibility
    pub version: u32,
    /// Collection of CEL rules
    pub rules: Vec<Rule>,
    /// Optional metadata about the bundle
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BundleMetadata>,
}

/// Individual CEL rule definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Rule {
    /// Unique rule identifier
    pub name: String,
    /// CEL expression to evaluate
    pub expr: String,
    /// Whether rule is active (default: true)
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Optional human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional tags for categorization
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Bundle metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BundleMetadata {
    /// Bundle name/title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Bundle description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Bundle author/organization
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Bundle version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_version: Option<String>,
    /// Creation timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
}

/// Compiled rule set ready for evaluation
#[derive(Debug)]
pub struct RuleSet {
    /// Map of rule name to compiled program
    pub programs: HashMap<String, CompiledRule>,
    /// Bundle metadata for debugging
    pub metadata: Option<BundleMetadata>,
    /// Load timestamp
    pub loaded_at: std::time::SystemTime,
}

/// Compiled CEL rule with actual CEL program
#[derive(Debug)]
pub struct CompiledRule {
    /// Original rule definition
    pub rule: Rule,
    /// Compiled CEL program ready for evaluation
    pub program: ::cel::Program,
    /// Estimated evaluation cost
    pub estimated_cost: u64,
    /// Compilation time in microseconds
    pub compile_time_us: u64,
}

fn default_enabled() -> bool {
    true
}

impl RuleBundle {
    /// Validate bundle structure and rules
    pub fn validate(&self) -> Result<(), String> {
        // Check version
        if self.version != 1 {
            return Err(format!("Unsupported bundle version: {}", self.version));
        }

        // Check for empty rules
        if self.rules.is_empty() {
            return Err("Bundle contains no rules".to_string());
        }

        // Check for duplicate rule names
        let mut seen_names = std::collections::HashSet::new();
        for rule in &self.rules {
            if rule.name.is_empty() {
                return Err("Rule name cannot be empty".to_string());
            }
            if rule.expr.is_empty() {
                return Err(format!("Rule '{}' has empty expression", rule.name));
            }
            if !seen_names.insert(&rule.name) {
                return Err(format!("Duplicate rule name: '{}'", rule.name));
            }
        }

        Ok(())
    }

    /// Parse bundle from YAML string
    pub fn from_yaml(content: &str) -> Result<Self, String> {
        serde_yaml::from_str(content)
            .map_err(|e| format!("YAML parsing error: {}", e))
    }

    /// Parse bundle from JSON string
    pub fn from_json(content: &str) -> Result<Self, String> {
        serde_json::from_str(content)
            .map_err(|e| format!("JSON parsing error: {}", e))
    }

    /// Serialize bundle to YAML
    pub fn to_yaml(&self) -> Result<String, String> {
        serde_yaml::to_string(self)
            .map_err(|e| format!("YAML serialization error: {}", e))
    }

    /// Serialize bundle to JSON
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialization error: {}", e))
    }
}

impl RuleSet {
    /// Create new empty rule set
    pub fn new() -> Self {
        Self {
            programs: HashMap::new(),
            metadata: None,
            loaded_at: std::time::SystemTime::now(),
        }
    }

    /// Get compiled rule by name
    pub fn get_rule(&self, name: &str) -> Option<&CompiledRule> {
        self.programs.get(name)
    }

    /// Get all rule names
    pub fn rule_names(&self) -> Vec<&String> {
        self.programs.keys().collect()
    }

    /// Get number of rules
    pub fn rule_count(&self) -> usize {
        self.programs.len()
    }

    /// Get enabled rule count
    pub fn enabled_rule_count(&self) -> usize {
        self.programs.values()
            .filter(|rule| rule.rule.enabled)
            .count()
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_bundle_yaml_parsing() {
        let yaml = r#"
version: 1
rules:
  - name: block_scanners
    expr: request.user_agent.matches('(?i)curl|sqlmap')
    description: Block automated scanners
  - name: block_admin
    expr: request.path.startsWith('/admin')
    enabled: false
metadata:
  name: Security Rules
  author: Security Team
"#;

        let bundle = RuleBundle::from_yaml(yaml).unwrap();
        assert_eq!(bundle.version, 1);
        assert_eq!(bundle.rules.len(), 2);
        assert_eq!(bundle.rules[0].name, "block_scanners");
        assert!(bundle.rules[0].enabled);
        assert!(!bundle.rules[1].enabled);
        assert!(bundle.metadata.is_some());
    }

    #[test]
    fn test_rule_bundle_json_parsing() {
        let json = r#"{
  "version": 1,
  "rules": [
    {
      "name": "test_rule",
      "expr": "true",
      "enabled": true
    }
  ]
}"#;

        let bundle = RuleBundle::from_json(json).unwrap();
        assert_eq!(bundle.version, 1);
        assert_eq!(bundle.rules.len(), 1);
        assert_eq!(bundle.rules[0].name, "test_rule");
    }

    #[test]
    fn test_bundle_validation() {
        let mut bundle = RuleBundle {
            version: 1,
            rules: vec![
                Rule {
                    name: "rule1".to_string(),
                    expr: "true".to_string(),
                    enabled: true,
                    description: None,
                    tags: vec![],
                },
            ],
            metadata: None,
        };

        assert!(bundle.validate().is_ok());

        // Test empty rules
        bundle.rules.clear();
        assert!(bundle.validate().is_err());

        // Test duplicate names
        bundle.rules = vec![
            Rule {
                name: "same_name".to_string(),
                expr: "true".to_string(),
                enabled: true,
                description: None,
                tags: vec![],
            },
            Rule {
                name: "same_name".to_string(),
                expr: "false".to_string(),
                enabled: true,
                description: None,
                tags: vec![],
            },
        ];
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_rule_set_operations() {
        let mut rule_set = RuleSet::new();
        assert_eq!(rule_set.rule_count(), 0);

        // Create a simple test program for testing
        let test_program = ::cel::Program::compile("true").expect("Failed to compile test program");
        let rule = CompiledRule {
            rule: Rule {
                name: "test".to_string(),
                expr: "true".to_string(),
                enabled: true,
                description: None,
                tags: vec![],
            },
            program: test_program,
            estimated_cost: 10,
            compile_time_us: 100,
        };

        rule_set.programs.insert("test".to_string(), rule);
        assert_eq!(rule_set.rule_count(), 1);
        assert!(rule_set.get_rule("test").is_some());
        assert!(rule_set.get_rule("missing").is_none());
    }
}