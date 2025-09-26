use std::collections::HashMap;
use varnish::vcl::Ctx;
use varnish_sys::vcl::StrOrBytes;

/// Helper function to convert StrOrBytes to String
fn str_or_bytes_to_string(value: StrOrBytes<'_>) -> String {
    match value {
        StrOrBytes::Utf8(s) => s.to_string(),
        StrOrBytes::Bytes(bytes) => {
            String::from_utf8(bytes.to_vec())
                .unwrap_or_else(|_| String::from_utf8_lossy(bytes).to_string())
        }
    }
}

/// Configuration for attribute extraction
#[derive(Debug, Clone)]
pub struct AttributeConfig {
    /// Extract cookies (opt-in due to performance cost)
    pub extract_cookies: bool,

    /// Maximum number of headers to process (DoS protection)
    pub max_headers: usize,

    /// Maximum size per header value (DoS protection)
    pub max_header_value_size: usize,

    /// Maximum number of cookies to parse
    pub max_cookie_count: usize,

    /// Maximum total size of all headers combined
    pub max_total_header_size: usize,
}

impl Default for AttributeConfig {
    fn default() -> Self {
        Self {
            extract_cookies: false,        // Opt-in for performance
            max_headers: 50,               // Reasonable limit
            max_header_value_size: 8192,   // 8KB per header
            max_cookie_count: 20,          // Reasonable cookie limit
            max_total_header_size: 65536,  // 64KB total headers
        }
    }
}

/// Normalized HTTP request attributes for CEL evaluation
#[derive(Debug, Clone)]
pub struct RequestAttrs {
    // Core request data (always extracted)
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub protocol: String,

    // Network information
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,

    // Headers (normalized: lowercase keys, combined multi-values)
    pub headers: HashMap<String, String>,

    // Optional attributes (configurable)
    pub cookies: Option<HashMap<String, String>>,

    // Metadata for debugging/metrics
    pub extraction_time_ns: u64,
    pub header_count: usize,
    pub total_size: usize,
}

impl RequestAttrs {
    /// Create empty RequestAttrs for testing
    pub fn empty() -> Self {
        Self {
            method: String::new(),
            path: String::new(),
            query: None,
            protocol: String::new(),
            client_ip: None,
            user_agent: None,
            headers: HashMap::new(),
            cookies: None,
            extraction_time_ns: 0,
            header_count: 0,
            total_size: 0,
        }
    }

    /// Get header value (case-insensitive lookup)
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(&name.to_lowercase())
    }

    /// Check if header exists (case-insensitive)
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.contains_key(&name.to_lowercase())
    }

    /// Get cookie value by name
    pub fn get_cookie(&self, name: &str) -> Option<&String> {
        self.cookies.as_ref()?.get(name)
    }

    /// Check if cookie exists
    pub fn has_cookie(&self, name: &str) -> bool {
        self.cookies.as_ref().map_or(false, |c| c.contains_key(name))
    }

    /// Get query parameter (simple key=value parsing)
    pub fn get_query_param(&self, param: &str) -> Option<String> {
        let query = self.query.as_ref()?;

        for pair in query.split('&') {
            if let Some(eq_pos) = pair.find('=') {
                let key = &pair[..eq_pos];
                if key == param {
                    let value = &pair[eq_pos + 1..];
                    return Some(urlencoding::decode(value).ok()?.to_string());
                }
            } else if pair == param {
                // Parameter with no value (e.g., ?debug)
                return Some(String::new());
            }
        }
        None
    }
}

/// Builder for extracting request attributes from Varnish context
pub struct AttributeBuilder {
    config: AttributeConfig,
}

impl AttributeBuilder {
    pub fn new(config: AttributeConfig) -> Self {
        Self { config }
    }

    pub fn with_default_config() -> Self {
        Self::new(AttributeConfig::default())
    }

    /// Extract request attributes from Varnish context
    pub fn extract(&self, ctx: &Ctx) -> Result<RequestAttrs, String> {
        let start_time = std::time::Instant::now();

        let req = ctx.http_req.as_ref()
            .ok_or_else(|| "No request context available".to_string())?;

        // Extract core request data
        let method = req.method()
            .map(|m| str_or_bytes_to_string(m))
            .unwrap_or_else(|| "UNKNOWN".to_string());

        let full_url = req.url()
            .map(|u| str_or_bytes_to_string(u))
            .unwrap_or_else(|| "/".to_string());

        let protocol = req.proto()
            .map(|p| str_or_bytes_to_string(p))
            .unwrap_or_else(|| "HTTP/1.1".to_string());

        // Parse URL into path and query
        let (path, query) = self.parse_url(&full_url);

        // Extract headers with normalization and safety limits
        let (headers, header_count, total_size) = self.extract_headers(req)?;

        // Extract network info
        let client_ip = self.extract_client_ip(req);
        let user_agent = req.header("user-agent")
            .map(|ua| str_or_bytes_to_string(ua));

        // Extract cookies if configured
        let cookies = if self.config.extract_cookies {
            self.extract_cookies(req)?
        } else {
            None
        };

        let extraction_time_ns = start_time.elapsed().as_nanos() as u64;

        Ok(RequestAttrs {
            method,
            path,
            query,
            protocol,
            client_ip,
            user_agent,
            headers,
            cookies,
            extraction_time_ns,
            header_count,
            total_size,
        })
    }

    /// Parse URL into path and query components
    pub fn parse_url(&self, url: &str) -> (String, Option<String>) {
        if let Some(query_pos) = url.find('?') {
            let path = url[..query_pos].to_string();
            let query = if query_pos + 1 < url.len() {
                Some(url[query_pos + 1..].to_string())
            } else {
                None
            };
            (path, query)
        } else {
            (url.to_string(), None)
        }
    }

    /// Extract and normalize headers with safety limits
    fn extract_headers(&self, req: &varnish::vcl::HttpHeaders) -> Result<(HashMap<String, String>, usize, usize), String> {
        let mut headers = HashMap::new();
        let mut header_count = 0;
        let mut total_size = 0;

        for (name, value) in req.iter() {
            if header_count >= self.config.max_headers {
                break;
            }

            let value_str = str_or_bytes_to_string(value);
            if value_str.len() > self.config.max_header_value_size {
                continue; // Skip oversized headers
            }

            if total_size + name.len() + value_str.len() > self.config.max_total_header_size {
                break; // Stop if total size would exceed limit
            }

            let key = name.to_lowercase();

            // Handle multi-value headers by combining with comma separation (RFC 7230)
            if let Some(existing) = headers.get(&key) {
                headers.insert(key, format!("{}, {}", existing, value_str));
            } else {
                headers.insert(key, value_str);
            }

            header_count += 1;
            total_size += name.len() + headers[&name.to_lowercase()].len();
        }

        Ok((headers, header_count, total_size))
    }

    /// Extract client IP from various sources
    fn extract_client_ip(&self, req: &varnish::vcl::HttpHeaders) -> Option<String> {
        // Priority order for IP extraction:
        // 1. X-Forwarded-For (first IP if comma-separated)
        // 2. X-Real-IP
        // 3. X-Client-IP
        // Note: Direct client.ip from Varnish would need to be passed as parameter

        if let Some(xff) = req.header("x-forwarded-for") {
            let xff_str = str_or_bytes_to_string(xff);
            // Take first IP from comma-separated list
            if let Some(first_ip) = xff_str.split(',').next() {
                return Some(first_ip.trim().to_string());
            }
        }

        if let Some(real_ip) = req.header("x-real-ip") {
            return Some(str_or_bytes_to_string(real_ip));
        }

        if let Some(client_ip) = req.header("x-client-ip") {
            return Some(str_or_bytes_to_string(client_ip));
        }

        None
    }

    /// Extract and parse cookies with safety limits
    fn extract_cookies(&self, req: &varnish::vcl::HttpHeaders) -> Result<Option<HashMap<String, String>>, String> {
        let cookie_header = match req.header("cookie") {
            Some(cookies) => str_or_bytes_to_string(cookies),
            None => return Ok(None),
        };

        let mut cookies = HashMap::new();
        let mut cookie_count = 0;

        for cookie_pair in cookie_header.split(';') {
            if cookie_count >= self.config.max_cookie_count {
                break;
            }

            let cookie_pair = cookie_pair.trim();
            if let Some(eq_pos) = cookie_pair.find('=') {
                let name = cookie_pair[..eq_pos].trim().to_string();
                let value = cookie_pair[eq_pos + 1..].trim().to_string();

                // Basic cookie value unquoting
                let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                    value[1..value.len()-1].to_string()
                } else {
                    value
                };

                cookies.insert(name, value);
                cookie_count += 1;
            }
        }

        Ok(if cookies.is_empty() { None } else { Some(cookies) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_request_attrs() {
        let attrs = RequestAttrs::empty();
        assert_eq!(attrs.method, "");
        assert_eq!(attrs.path, "");
        assert_eq!(attrs.query, None);
        assert_eq!(attrs.headers.len(), 0);
    }

    #[test]
    fn test_header_lookup() {
        let mut attrs = RequestAttrs::empty();
        attrs.headers.insert("content-type".to_string(), "application/json".to_string());

        assert_eq!(attrs.get_header("Content-Type"), Some(&"application/json".to_string()));
        assert_eq!(attrs.get_header("CONTENT-TYPE"), Some(&"application/json".to_string()));
        assert!(attrs.has_header("content-type"));
        assert!(attrs.has_header("Content-Type"));
        assert!(!attrs.has_header("authorization"));
    }

    #[test]
    fn test_query_param_parsing() {
        let mut attrs = RequestAttrs::empty();
        attrs.query = Some("foo=bar&baz=qux&flag&encoded=%20test".to_string());

        assert_eq!(attrs.get_query_param("foo"), Some("bar".to_string()));
        assert_eq!(attrs.get_query_param("baz"), Some("qux".to_string()));
        assert_eq!(attrs.get_query_param("flag"), Some("".to_string()));
        assert_eq!(attrs.get_query_param("encoded"), Some(" test".to_string()));
        assert_eq!(attrs.get_query_param("missing"), None);
    }

    #[test]
    fn test_url_parsing() {
        let builder = AttributeBuilder::with_default_config();

        let (path, query) = builder.parse_url("/api/v1/users");
        assert_eq!(path, "/api/v1/users");
        assert_eq!(query, None);

        let (path, query) = builder.parse_url("/search?q=rust&limit=10");
        assert_eq!(path, "/search");
        assert_eq!(query, Some("q=rust&limit=10".to_string()));

        let (path, query) = builder.parse_url("/empty?");
        assert_eq!(path, "/empty");
        assert_eq!(query, None);
    }

    #[test]
    fn test_attribute_config_defaults() {
        let config = AttributeConfig::default();
        assert!(!config.extract_cookies);
        assert_eq!(config.max_headers, 50);
        assert_eq!(config.max_header_value_size, 8192);
        assert_eq!(config.max_cookie_count, 20);
    }
}