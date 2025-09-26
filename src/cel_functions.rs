use crate::request_attrs::RequestAttrs;
use crate::safety_limits::{SafetyLimits, SafetyError};
use anyhow::{anyhow, Result};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

/// Custom CEL functions for HTTP request filtering
///
/// This module provides HTTP-specific functions that can be used in CEL expressions
/// to evaluate request attributes. All functions are designed to be safe, fast,
/// and deterministic.

/// Global registry for compiled regexes to avoid recompilation
lazy_static! {
    static ref REGEX_CACHE: RwLock<HashMap<String, Result<Regex, String>>> = RwLock::new(HashMap::new());
}

/// Custom CEL function context that holds request attributes
#[derive(Debug, Clone)]
pub struct CelFunctionContext {
    pub request: Arc<RequestAttrs>,
    pub limits: SafetyLimits,
}

impl CelFunctionContext {
    pub fn new(request: Arc<RequestAttrs>, limits: SafetyLimits) -> Self {
        Self { request, limits }
    }
}

/// Check if an IP address is within a CIDR range
///
/// # Examples
/// * `in_cidr("192.168.1.1", "192.168.0.0/16")` -> true
/// * `in_cidr("10.0.0.1", "192.168.0.0/24")` -> false
/// * `in_cidr("2001:db8::1", "2001:db8::/32")` -> true
///
/// # Errors
/// * Returns false if either IP or CIDR is invalid
/// * Returns false if IP version doesn't match CIDR version
pub fn in_cidr(ip_str: &str, cidr_str: &str) -> bool {
    // Parse IP address
    let ip = match IpAddr::from_str(ip_str) {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    // Parse CIDR network
    let network = match IpNet::from_str(cidr_str) {
        Ok(net) => net,
        Err(_) => return false,
    };

    // Check containment
    network.contains(&ip)
}

/// Check if an IPv4 address is within an IPv4 CIDR range (optimized version)
pub fn in_cidr_v4(ip_str: &str, cidr_str: &str) -> bool {
    let ip = match ip_str.parse::<std::net::Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    let network = match Ipv4Net::from_str(cidr_str) {
        Ok(net) => net,
        Err(_) => return false,
    };

    network.contains(&ip)
}

/// Check if an IPv6 address is within an IPv6 CIDR range (optimized version)
pub fn in_cidr_v6(ip_str: &str, cidr_str: &str) -> bool {
    let ip = match ip_str.parse::<std::net::Ipv6Addr>() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    let network = match Ipv6Net::from_str(cidr_str) {
        Ok(net) => net,
        Err(_) => return false,
    };

    network.contains(&ip)
}

/// Check if a header exists (case-insensitive)
///
/// # Examples
/// * `has_header("Content-Type")` -> true if Content-Type header exists
/// * `has_header("X-Custom-Header")` -> true if X-Custom-Header exists
pub fn has_header(ctx: &CelFunctionContext, name: &str) -> bool {
    ctx.request.has_header(name)
}

/// Check if a header equals a specific value (case-insensitive header name, case-sensitive value)
///
/// # Examples
/// * `header_eq("Content-Type", "application/json")` -> true if Content-Type is exactly "application/json"
/// * `header_eq("Authorization", "Bearer token123")` -> true if Authorization matches exactly
pub fn header_eq(ctx: &CelFunctionContext, name: &str, expected_value: &str) -> bool {
    match ctx.request.get_header(name) {
        Some(value) => value == expected_value,
        None => false,
    }
}

/// Check if a header value matches a regex pattern
///
/// # Examples
/// * `header_matches("User-Agent", "(?i)bot|crawler|spider")` -> true if User-Agent contains bot, crawler, or spider
/// * `header_matches("X-Forwarded-For", r"\d+\.\d+\.\d+\.\d+")` -> true if XFF contains an IP pattern
///
/// # Safety
/// * Regex patterns are limited in size by safety limits
/// * Compiled regexes are cached for performance
/// * Invalid regexes return false
pub fn header_matches(ctx: &CelFunctionContext, name: &str, pattern: &str) -> Result<bool, SafetyError> {
    // Check regex size limits
    ctx.limits.check_regex_size(pattern)?;

    let header_value = match ctx.request.get_header(name) {
        Some(value) => value,
        None => return Ok(false),
    };

    // Get or compile regex (with caching)
    let regex_result = {
        let cache = REGEX_CACHE.read().unwrap();
        cache.get(pattern).cloned()
    };

    let regex = match regex_result {
        Some(Ok(regex)) => regex,
        Some(Err(_)) => return Ok(false), // Previously failed to compile
        None => {
            // Need to compile and cache
            let compile_result = Regex::new(pattern);
            let mut cache = REGEX_CACHE.write().unwrap();

            match compile_result {
                Ok(regex) => {
                    cache.insert(pattern.to_string(), Ok(regex.clone()));
                    regex
                }
                Err(e) => {
                    cache.insert(pattern.to_string(), Err(e.to_string()));
                    return Ok(false);
                }
            }
        }
    };

    Ok(regex.is_match(header_value))
}

/// Check if a string value is in a list of strings
///
/// # Examples
/// * `in_list("GET", ["GET", "POST", "PUT"])` -> true
/// * `in_list("DELETE", ["GET", "POST"])` -> false
pub fn in_list(value: &str, list: &[&str]) -> bool {
    list.contains(&value)
}

/// Check if a string starts with any of the given prefixes
///
/// # Examples
/// * `starts_with_any("/api/v1/users", ["/api/v1", "/api/v2"])` -> true
/// * `starts_with_any("/admin", ["/api", "/health"])` -> false
pub fn starts_with_any(value: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| value.starts_with(prefix))
}

/// Check if a string ends with any of the given suffixes
///
/// # Examples
/// * `ends_with_any("/path/file.json", [".json", ".xml"])` -> true
/// * `ends_with_any("/path/file.txt", [".json", ".xml"])` -> false
pub fn ends_with_any(value: &str, suffixes: &[&str]) -> bool {
    suffixes.iter().any(|suffix| value.ends_with(suffix))
}

/// Check if a string contains any of the given substrings
///
/// # Examples
/// * `contains_any("Mozilla/5.0 Bot", ["bot", "crawler"])` -> true (case-sensitive)
/// * `contains_any("normal browser", ["bot", "crawler"])` -> false
pub fn contains_any(value: &str, substrings: &[&str]) -> bool {
    substrings.iter().any(|substring| value.contains(substring))
}

/// Case-insensitive version of contains_any
///
/// # Examples
/// * `contains_any_i("Mozilla/5.0 BOT", ["bot", "crawler"])` -> true
/// * `contains_any_i("Normal Browser", ["bot", "crawler"])` -> false
pub fn contains_any_i(value: &str, substrings: &[&str]) -> bool {
    let value_lower = value.to_lowercase();
    substrings.iter().any(|substring| value_lower.contains(&substring.to_lowercase()))
}

/// Get the client IP from request (helper function for CEL expressions)
///
/// Returns the client IP extracted from various headers or empty string if not available
pub fn client_ip(ctx: &CelFunctionContext) -> String {
    ctx.request.client_ip.clone().unwrap_or_default()
}

/// Get HTTP method from request
pub fn http_method(ctx: &CelFunctionContext) -> String {
    ctx.request.method.clone()
}

/// Get request path from URL
pub fn request_path(ctx: &CelFunctionContext) -> String {
    ctx.request.path.clone()
}

/// Get query string from request
pub fn query_string(ctx: &CelFunctionContext) -> String {
    ctx.request.query.clone().unwrap_or_default()
}

/// Get User-Agent header value
pub fn user_agent(ctx: &CelFunctionContext) -> String {
    ctx.request.user_agent.clone().unwrap_or_default()
}

/// Get a specific query parameter value
///
/// # Examples
/// * `query_param("page")` -> "1" if URL is "/search?page=1&q=rust"
/// * `query_param("missing")` -> "" if parameter doesn't exist
pub fn query_param(ctx: &CelFunctionContext, param: &str) -> String {
    ctx.request.get_query_param(param).unwrap_or_default()
}

/// Check if request has a specific cookie
pub fn has_cookie(ctx: &CelFunctionContext, name: &str) -> bool {
    ctx.request.has_cookie(name)
}

/// Get a specific cookie value
pub fn cookie_value(ctx: &CelFunctionContext, name: &str) -> String {
    ctx.request.get_cookie(name).cloned().unwrap_or_default()
}

/// Check if request path matches a glob pattern
///
/// # Examples
/// * `path_matches("/api/*/users")` -> true for "/api/v1/users"
/// * `path_matches("/admin/**")` -> true for any path under /admin/
pub fn path_matches(ctx: &CelFunctionContext, pattern: &str) -> Result<bool, SafetyError> {
    // Convert glob pattern to regex
    let regex_pattern = glob_to_regex(pattern)?;

    // Check pattern size
    ctx.limits.check_regex_size(&regex_pattern)?;

    // Compile and match
    match Regex::new(&regex_pattern) {
        Ok(regex) => Ok(regex.is_match(&ctx.request.path)),
        Err(_) => Ok(false),
    }
}

/// Convert a simple glob pattern to regex
///
/// Supports:
/// * `*` - matches any characters except /
/// * `**` - matches any characters including /
/// * `?` - matches single character except /
fn glob_to_regex(pattern: &str) -> Result<String, SafetyError> {
    let mut regex = String::with_capacity(pattern.len() * 2);
    regex.push('^');

    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '*' => {
                if i + 1 < chars.len() && chars[i + 1] == '*' {
                    // ** matches any characters including /
                    regex.push_str(".*");
                    i += 2;
                } else {
                    // * matches any characters except /
                    regex.push_str("[^/]*");
                    i += 1;
                }
            }
            '?' => {
                // ? matches single character except /
                regex.push_str("[^/]");
                i += 1;
            }
            // Escape special regex characters
            '.' | '+' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' => {
                regex.push('\\');
                regex.push(chars[i]);
                i += 1;
            }
            c => {
                regex.push(c);
                i += 1;
            }
        }
    }

    regex.push('$');
    Ok(regex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_attrs::RequestAttrs;
    use std::collections::HashMap;

    fn create_test_context() -> CelFunctionContext {
        let mut attrs = RequestAttrs::empty();
        attrs.method = "GET".to_string();
        attrs.path = "/api/v1/users".to_string();
        attrs.query = Some("page=1&limit=10".to_string());
        attrs.client_ip = Some("192.168.1.100".to_string());
        attrs.user_agent = Some("Mozilla/5.0 (compatible; TestBot/1.0)".to_string());

        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("authorization".to_string(), "Bearer token123".to_string());
        headers.insert("user-agent".to_string(), "Mozilla/5.0 (compatible; TestBot/1.0)".to_string());
        attrs.headers = headers;

        CelFunctionContext::new(Arc::new(attrs), SafetyLimits::default())
    }

    #[test]
    fn test_in_cidr() {
        assert!(in_cidr("192.168.1.1", "192.168.0.0/16"));
        assert!(in_cidr("192.168.255.255", "192.168.0.0/16"));
        assert!(!in_cidr("10.0.0.1", "192.168.0.0/16"));
        assert!(!in_cidr("invalid-ip", "192.168.0.0/16"));
        assert!(!in_cidr("192.168.1.1", "invalid-cidr"));
    }

    #[test]
    fn test_in_cidr_v6() {
        assert!(in_cidr("2001:db8::1", "2001:db8::/32"));
        assert!(in_cidr("2001:db8:ffff::1", "2001:db8::/32"));
        assert!(!in_cidr("2001:db9::1", "2001:db8::/32"));
    }

    #[test]
    fn test_has_header() {
        let ctx = create_test_context();

        assert!(has_header(&ctx, "Content-Type"));
        assert!(has_header(&ctx, "content-type"));
        assert!(has_header(&ctx, "Authorization"));
        assert!(!has_header(&ctx, "X-Missing-Header"));
    }

    #[test]
    fn test_header_eq() {
        let ctx = create_test_context();

        assert!(header_eq(&ctx, "Content-Type", "application/json"));
        assert!(!header_eq(&ctx, "Content-Type", "text/html"));
        assert!(!header_eq(&ctx, "Missing-Header", "value"));
    }

    #[test]
    fn test_header_matches() {
        let ctx = create_test_context();

        assert!(header_matches(&ctx, "User-Agent", r".*Bot.*").unwrap());
        assert!(header_matches(&ctx, "User-Agent", r"(?i)mozilla").unwrap());
        assert!(!header_matches(&ctx, "User-Agent", r"Chrome").unwrap());
        assert!(!header_matches(&ctx, "Missing-Header", r".*").unwrap());
    }

    #[test]
    fn test_in_list() {
        assert!(in_list("GET", &["GET", "POST", "PUT"]));
        assert!(!in_list("DELETE", &["GET", "POST", "PUT"]));
        assert!(!in_list("GET", &[]));
    }

    #[test]
    fn test_starts_with_any() {
        assert!(starts_with_any("/api/v1/users", &["/api/v1", "/admin"]));
        assert!(starts_with_any("/admin/panel", &["/api", "/admin"]));
        assert!(!starts_with_any("/public/file", &["/api", "/admin"]));
    }

    #[test]
    fn test_contains_any_i() {
        assert!(contains_any_i("Mozilla/5.0 BOT", &["bot", "crawler"]));
        assert!(contains_any_i("Spider-Bot/1.0", &["bot", "crawler"]));
        assert!(!contains_any_i("Normal Browser", &["bot", "crawler"]));
    }

    #[test]
    fn test_context_functions() {
        let ctx = create_test_context();

        assert_eq!(client_ip(&ctx), "192.168.1.100");
        assert_eq!(http_method(&ctx), "GET");
        assert_eq!(request_path(&ctx), "/api/v1/users");
        assert_eq!(query_string(&ctx), "page=1&limit=10");
        assert_eq!(query_param(&ctx, "page"), "1");
        assert_eq!(query_param(&ctx, "limit"), "10");
        assert_eq!(query_param(&ctx, "missing"), "");
    }

    #[test]
    fn test_glob_to_regex() {
        assert_eq!(glob_to_regex("/api/*").unwrap(), "^/api/[^/]*$");
        assert_eq!(glob_to_regex("/api/**").unwrap(), "^/api/.*$");
        assert_eq!(glob_to_regex("/api/*/users").unwrap(), "^/api/[^/]*/users$");
        assert_eq!(glob_to_regex("/api/v?/users").unwrap(), "^/api/v[^/]/users$");
    }

    #[test]
    fn test_path_matches() {
        let ctx = create_test_context();

        // Path is "/api/v1/users"
        assert!(!path_matches(&ctx, "/api/*").unwrap());    // Should NOT match - * doesn't cross directory boundaries
        assert!(path_matches(&ctx, "/api/**").unwrap());    // Should match - ** matches everything
        assert!(path_matches(&ctx, "/api/*/users").unwrap()); // Should match - v1 matches *
        assert!(!path_matches(&ctx, "/admin/*").unwrap());   // Should NOT match - different path
    }
}