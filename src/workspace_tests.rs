#[cfg(test)]
mod workspace_tests {
    use super::workspace::WorkspaceConfig;

    #[test]
    fn test_workspace_config_default() {
        let config = WorkspaceConfig::default();
        assert_eq!(config.max_headers, 50);
        assert_eq!(config.max_cookies, 20);
        assert_eq!(config.max_string_size, 8192);
    }

    #[test]
    fn test_workspace_config_custom() {
        let config = WorkspaceConfig {
            max_headers: 100,
            max_cookies: 40,
            max_string_size: 16384,
        };
        assert_eq!(config.max_headers, 100);
        assert_eq!(config.max_cookies, 40);
        assert_eq!(config.max_string_size, 16384);
    }

    // Note: More comprehensive tests would require a mock Varnish workspace
    // For now, the compilation success of the workspace module is the main test
    #[test]
    fn test_workspace_module_compiles() {
        // This test ensures the workspace module compiles correctly
        // The actual functionality would need integration tests with Varnish
        assert!(true);
    }
}