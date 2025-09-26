use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::NamedTempFile;
use vmod_cel::{BundleFormat, BundleLoader, LoadError, RuleSetSwapper};

#[test]
fn test_load_example_bundle() {
    let loader = BundleLoader::new().expect("Failed to create loader");
    let result = loader.load_file("tests/bundle_example.yaml");

    assert!(
        result.is_ok(),
        "Failed to load example bundle: {:?}",
        result.err()
    );

    let rule_set = result.unwrap();
    assert_eq!(rule_set.rule_count(), 3); // Only enabled rules loaded
    assert!(rule_set.get_rule("block_scanners").is_some());
    assert!(rule_set.get_rule("block_admin_paths").is_some());
    assert!(rule_set.get_rule("block_suspicious_ips").is_some());
    assert!(rule_set.get_rule("rate_limit_api").is_none()); // Disabled rule
}

#[test]
fn test_load_malformed_bundle() {
    let loader = BundleLoader::new().expect("Failed to create loader");
    let result = loader.load_file("tests/bundle_malformed.yaml");

    assert!(result.is_err(), "Should fail to load malformed bundle");

    match result.unwrap_err() {
        LoadError::ValidationError(_) => {} // Expected
        other => panic!("Expected ValidationError, got: {:?}", other),
    }
}

#[test]
fn test_atomic_swapping() {
    let swapper = RuleSetSwapper::new();

    // Initial state should be empty
    assert_eq!(swapper.get().rule_count(), 0);

    // Load valid bundle
    let result = swapper.load_and_swap("tests/bundle_example.yaml");
    assert!(
        result.is_ok(),
        "Failed to load and swap: {:?}",
        result.err()
    );

    // Verify rules were loaded
    let current = swapper.get();
    assert_eq!(current.rule_count(), 3);

    // Try to load malformed bundle - should keep old rules
    let bad_result = swapper.load_and_swap("tests/bundle_malformed.yaml");
    assert!(bad_result.is_err(), "Should fail to load malformed bundle");

    // Verify old rules are still there
    let still_current = swapper.get();
    assert_eq!(still_current.rule_count(), 3);
}

#[test]
fn test_concurrent_access() {
    let swapper = Arc::new(RuleSetSwapper::new());
    let swapper_clone = swapper.clone();

    // Load initial rules
    let _ = swapper.load_and_swap("tests/bundle_example.yaml");

    // Spawn multiple threads accessing rules
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let swapper = swapper.clone();
            thread::spawn(move || {
                for _ in 0..100 {
                    let rules = swapper.get();
                    assert!(rules.rule_count() > 0);
                    // Small delay to increase chance of concurrent access
                    thread::sleep(Duration::from_micros(1));
                }
                i
            })
        })
        .collect();

    // While other threads are reading, try to swap rules
    thread::spawn(move || {
        for _ in 0..5 {
            let _ = swapper_clone.load_and_swap("tests/bundle_example.yaml");
            thread::sleep(Duration::from_millis(10));
        }
    });

    // Wait for all reader threads
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_background_loading() {
    let loader = BundleLoader::new().expect("Failed to create loader");
    let result = Arc::new(Mutex::new(None));
    let result_clone = result.clone();

    // Load in background
    loader.load_file_async(
        "tests/bundle_example.yaml",
        Box::new(move |load_result| {
            *result_clone.lock().unwrap() = Some(load_result);
        }),
    );

    // Wait for background thread to complete
    let mut attempts = 0;
    loop {
        {
            let guard = result.lock().unwrap();
            if guard.is_some() {
                break;
            }
        }
        thread::sleep(Duration::from_millis(10));
        attempts += 1;
        assert!(attempts < 1000, "Background loading took too long");
    }

    // Verify result
    let final_result = result.lock().unwrap().take().unwrap();
    assert!(final_result.is_ok());
}

#[test]
fn test_json_format_support() -> Result<(), Box<dyn std::error::Error>> {
    let json_content = r#"{
  "version": 1,
  "rules": [
    {
      "name": "json_test_rule",
      "expr": "request.method == \"GET\"",
      "enabled": true,
      "description": "Test rule from JSON"
    }
  ],
  "metadata": {
    "name": "JSON Test Bundle"
  }
}"#;

    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(json_content.as_bytes())?;

    // Rename to .json extension
    let json_path = temp_file.path().with_extension("json");
    std::fs::copy(temp_file.path(), &json_path)?;

    let loader = BundleLoader::new().expect("Failed to create loader");
    let result = loader.load_file(&json_path);

    std::fs::remove_file(json_path)?;

    assert!(
        result.is_ok(),
        "Failed to load JSON bundle: {:?}",
        result.err()
    );

    let rule_set = result.unwrap();
    assert_eq!(rule_set.rule_count(), 1);
    assert!(rule_set.get_rule("json_test_rule").is_some());

    Ok(())
}

#[test]
fn test_blob_loading() {
    let yaml_content = r#"
version: 1
rules:
  - name: blob_test
    expr: "true"
    enabled: true
"#;

    let loader = BundleLoader::new().expect("Failed to create loader");
    let result = loader.load_blob(yaml_content, BundleFormat::Yaml);

    assert!(result.is_ok());
    let rule_set = result.unwrap();
    assert_eq!(rule_set.rule_count(), 1);
    assert!(rule_set.get_rule("blob_test").is_some());
}

#[test]
fn test_rule_metadata_preservation() {
    let loader = BundleLoader::new().expect("Failed to create loader");
    let result = loader.load_file("tests/bundle_example.yaml");

    assert!(result.is_ok());
    let rule_set = result.unwrap();

    // Check that metadata is preserved
    assert!(rule_set.metadata.is_some());
    let metadata = rule_set.metadata.as_ref().unwrap();
    assert_eq!(metadata.name.as_deref(), Some("Example Security Rules"));
    assert_eq!(metadata.author.as_deref(), Some("Security Team"));
}

#[test]
fn test_unsupported_file_format() {
    let loader = BundleLoader::new().expect("Failed to create loader");

    // Create a file with unsupported extension
    let result = loader.load_file("tests/bundle_example.txt");
    assert!(matches!(result, Err(LoadError::UnsupportedFormat(_))));
}
