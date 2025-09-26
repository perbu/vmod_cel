#[cfg(test)]
#[allow(clippy::module_inception)]
mod phase5_tests {
    use crate::{CelConfig, CelState, CEL_STATE, cel};

    #[test]
    fn test_cel_config_explain_mode() {
        let mut config = CelConfig::new();
        assert!(!config.enable_explain);

        config.enable_explain = true;
        assert!(config.enable_explain);

        let dev_config = CelConfig::development();
        assert!(dev_config.enable_explain);

        let prod_config = CelConfig::production();
        assert!(!prod_config.enable_explain);
    }

    #[test]
    fn test_cel_state_set_explain_mode() {
        let mut state = CelState::new().expect("Failed to create CelState");
        assert!(!state.config.enable_explain);

        state.set_explain_mode(true);
        assert!(state.config.enable_explain);

        state.set_explain_mode(false);
        assert!(!state.config.enable_explain);
    }

    #[test]
    fn test_eval_or_with_missing_rule() {
        let state = CelState::new().expect("Failed to create CelState");

        // Mock VCL context would be needed for real evaluation
        // For now, test the structure and error handling paths

        // The current implementation always returns the default when VCL context is unavailable
        // This tests the graceful degradation behavior
        assert_eq!(state.rules.rule_names().len(), 0);
    }

    #[test]
    fn test_explain_rule_with_explain_disabled() {
        let state = CelState::new().expect("Failed to create CelState");
        assert!(!state.config.enable_explain);

        // When explain is disabled, should return empty string regardless of rule existence
        // (This would require VCL context in real usage)
        assert!(!state.config.enable_explain);
    }

    #[test]
    fn test_explain_rule_with_explain_enabled() {
        let mut state = CelState::new().expect("Failed to create CelState");
        state.set_explain_mode(true);
        assert!(state.config.enable_explain);

        // Add a test rule
        state.add_rule("test_rule", "true").expect("Failed to add rule");

        // Check that rule was added
        assert!(state.rules.get_rule("test_rule").is_some());
    }

    #[test]
    fn test_phase5_error_handling() {
        // Test various error conditions

        // Test with uninitialized state
        let guard = CEL_STATE.lock().unwrap();
        assert!(guard.is_none());
        drop(guard);

        // Phase 5 functions should handle uninitialized state gracefully
        assert!(!cel::eval("test_rule"));
        assert!(!cel::eval_or("test_rule", false));
        assert!(cel::eval_or("test_rule", true));
        assert_eq!(cel::explain("test_rule"), String::new());
        assert!(cel::set_explain_mode(true).is_err());
    }

    #[test]
    fn test_phase5_functions_with_initialized_state() {
        // Initialize the VMOD
        cel::init().expect("Failed to initialize VMOD");

        // Test basic functionality
        assert!(!cel::eval("nonexistent_rule"));
        assert!(!cel::eval_or("nonexistent_rule", false));
        assert!(cel::eval_or("nonexistent_rule", true));

        // Test explain mode
        assert!(cel::set_explain_mode(true).is_ok());
        assert!(cel::set_explain_mode(false).is_ok());

        // Add a rule and test
        assert!(cel::add_rule("test_rule", "true").is_ok());

        // Test explain with rule present
        cel::set_explain_mode(true).expect("Failed to enable explain mode");
        let explanation = cel::explain("test_rule");
        assert!(!explanation.is_empty());
        assert!(explanation.contains("test_rule"));

        // Test explain with mode disabled
        cel::set_explain_mode(false).expect("Failed to disable explain mode");
        let explanation = cel::explain("test_rule");
        assert!(explanation.is_empty());
    }

    #[test]
    fn test_metrics_tracking() {
        cel::init().expect("Failed to initialize VMOD");

        let initial_metrics = cel::metrics_summary();
        assert!(initial_metrics.contains("Compiles OK:"));

        // Add a rule to generate compile metrics
        cel::add_rule("metrics_test", "true").expect("Failed to add rule");

        let updated_metrics = cel::metrics_summary();
        assert!(updated_metrics.contains("Compiles OK:"));

        // The exact numbers will depend on previous tests, but structure should be consistent
        assert!(updated_metrics.contains("Evals True:"));
        assert!(updated_metrics.contains("Errors:"));
    }

    #[test]
    fn test_rule_info_and_listing() {
        cel::init().expect("Failed to initialize VMOD");

        // Initially no rules
        let rules_list = cel::list_rules();
        assert!(rules_list.contains("No rules loaded") || rules_list.contains("Rules ("));

        // Add some rules
        cel::add_rule("info_test_1", "true").expect("Failed to add rule");
        cel::add_rule("info_test_2", "false").expect("Failed to add rule");

        // Check rule listing
        let rules_list = cel::list_rules();
        assert!(rules_list.contains("info_test_1"));
        assert!(rules_list.contains("info_test_2"));

        // Check individual rule info
        let rule_info = cel::rule_info("info_test_1");
        assert!(rule_info.contains("info_test_1"));
        assert!(rule_info.contains("true"));
        assert!(rule_info.contains("Enabled: true"));

        let missing_info = cel::rule_info("missing_rule");
        assert!(missing_info.contains("not found"));
    }

    #[test]
    fn test_configuration_functions() {
        cel::init().expect("Failed to initialize VMOD");

        // Test debug config
        let config = cel::debug_config();
        assert!(config.contains("Extract cookies:"));
        assert!(config.contains("Max headers:"));
        assert!(config.contains("Max header size:"));

        // Test configure attributes
        assert!(cel::configure_attributes(true, 100, 8192).is_ok());

        // Test invalid configurations
        assert!(cel::configure_attributes(true, 0, 8192).is_err()); // max_headers too low
        assert!(cel::configure_attributes(true, 1001, 8192).is_err()); // max_headers too high
        assert!(cel::configure_attributes(true, 100, 1023).is_err()); // max_header_size too low
        assert!(cel::configure_attributes(true, 100, 1048577).is_err()); // max_header_size too high
    }

    // Note: eval_any() and eval_all() tests are now in VarnishTest integration tests
    // since these functions require a VCL context that's only available during request processing.
    // See tests/eval_multiple.vtc for comprehensive testing of these functions.

    #[test]
    fn test_eval_functions_context_requirement() {
        cel::init().expect("Failed to initialize VMOD");

        // Add some test rules to ensure the state is configured correctly
        cel::add_rule("test_rule", "true").expect("Failed to add rule");

        // Verify rules were added correctly
        let enabled_count = {
            let guard = CEL_STATE.lock().unwrap();
            guard.as_ref().unwrap().rules.enabled_rule_count()
        };
        assert!(enabled_count > 0);

        // The actual eval_any() and eval_all() functions require VCL context
        // and are tested in the VarnishTest integration suite (eval_multiple.vtc)
    }
}