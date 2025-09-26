use varnish::vcl::{Ctx, VclError, Workspace};
use varnish_sys::vcl::StrOrBytes;
use crate::workspace::{WsHashMap, WsString};


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
            extract_cookies: false,       // Opt-in for performance
            max_headers: 50,              // Reasonable limit
            max_header_value_size: 8192,  // 8KB per header
            max_cookie_count: 20,         // Reasonable cookie limit
            max_total_header_size: 65536, // 64KB total headers
        }
    }
}


/// Workspace-backed HTTP request attributes for CEL evaluation
/// This version uses Varnish workspace allocation to avoid heap allocations
#[derive(Debug)]
pub struct WsRequestAttrs<'ctx> {
    // Core request data (always extracted)
    pub method: WsString<'ctx>,
    pub path: WsString<'ctx>,
    pub query: Option<WsString<'ctx>>,
    pub protocol: WsString<'ctx>,

    // Network information
    pub client_ip: Option<WsString<'ctx>>,
    pub user_agent: Option<WsString<'ctx>>,

    // Headers (normalized: lowercase keys, combined multi-values)
    pub headers: WsHashMap<'ctx>,

    // Optional attributes (configurable)
    pub cookies: Option<WsHashMap<'ctx>>,

    // Metadata for debugging/metrics
    pub extraction_time_ns: u64,
    pub header_count: usize,
    pub total_size: usize,
}


impl<'ctx> WsRequestAttrs<'ctx> {
    /// Get header value (case-insensitive lookup)
    pub fn get_header(&self, name: &str) -> Option<&WsString<'ctx>> {
        self.headers.get(name)
    }

    /// Check if header exists (case-insensitive)
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.contains_key(name)
    }

    /// Get cookie value by name
    pub fn get_cookie(&self, name: &str) -> Option<&WsString<'ctx>> {
        self.cookies.as_ref()?.get(name)
    }

    /// Check if cookie exists
    pub fn has_cookie(&self, name: &str) -> bool {
        self.cookies.as_ref().is_some_and(|c| c.contains_key(name))
    }

    /// Get query parameter (simple key=value parsing)
    pub fn get_query_param(&self, param: &str, ws: &mut Workspace<'ctx>) -> Option<WsString<'ctx>> {
        let query = self.query.as_ref()?;
        let query_str = query.as_str();

        for pair in query_str.split('&') {
            if let Some(eq_pos) = pair.find('=') {
                let key = &pair[..eq_pos];
                if key == param {
                    let value = &pair[eq_pos + 1..];
                    // URL decode the value - for now, simple implementation
                    if let Ok(decoded) = urlencoding::decode(value) {
                        return WsString::new(ws, &decoded).ok();
                    }
                }
            } else if pair == param {
                // Parameter with no value (e.g., ?debug)
                return WsString::new(ws, "").ok();
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

    /// Extract request attributes from Varnish context using workspace allocation
    pub fn extract_ws<'ctx>(&self, ctx: &mut Ctx<'ctx>) -> Result<WsRequestAttrs<'ctx>, VclError> {
        let start_time = std::time::Instant::now();

        let req = ctx
            .http_req
            .as_ref()
            .ok_or_else(|| VclError::String("No request context available".to_string()))?;

        let ws = &mut ctx.ws;

        // Extract core request data using workspace
        let method = match req.method() {
            Some(m) => WsString::from_str_or_bytes(ws, m)?,
            None => WsString::new(ws, "UNKNOWN")?,
        };

        let full_url = match req.url() {
            Some(u) => WsString::from_str_or_bytes(ws, u)?,
            None => WsString::new(ws, "/")?,
        };

        let protocol = match req.proto() {
            Some(p) => WsString::from_str_or_bytes(ws, p)?,
            None => WsString::new(ws, "HTTP/1.1")?,
        };

        // Parse URL into path and query
        let (path, query) = self.parse_url_ws(ws, full_url.as_str())?;

        // Extract headers with normalization and safety limits using workspace
        let (headers, header_count, total_size) = self.extract_headers_ws(ws, req)?;

        // Extract network info
        let client_ip = self.extract_client_ip_ws(ws, req)?;
        let user_agent = match req.header("user-agent") {
            Some(ua) => Some(WsString::from_str_or_bytes(ws, ua)?),
            None => None,
        };

        // Extract cookies if configured
        let cookies = if self.config.extract_cookies {
            self.extract_cookies_ws(ws, req)?
        } else {
            None
        };

        let extraction_time_ns = start_time.elapsed().as_nanos() as u64;

        Ok(WsRequestAttrs {
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


    /// Parse URL into path and query components using workspace allocation
    fn parse_url_ws<'ctx>(&self, ws: &mut Workspace<'ctx>, url: &str) -> Result<(WsString<'ctx>, Option<WsString<'ctx>>), VclError> {
        if let Some(query_pos) = url.find('?') {
            let path = WsString::new(ws, &url[..query_pos])?;
            let query = if query_pos + 1 < url.len() {
                Some(WsString::new(ws, &url[query_pos + 1..])?)
            } else {
                None
            };
            Ok((path, query))
        } else {
            let path = WsString::new(ws, url)?;
            Ok((path, None))
        }
    }


    /// Extract and normalize headers with safety limits using workspace
    fn extract_headers_ws<'ctx>(
        &self,
        ws: &mut Workspace<'ctx>,
        req: &varnish::vcl::HttpHeaders,
    ) -> Result<(WsHashMap<'ctx>, usize, usize), VclError> {
        let mut headers = WsHashMap::new(ws, self.config.max_headers)?;
        let mut header_count = 0;
        let mut total_size = 0;

        for (name, value) in req.iter() {
            if header_count >= self.config.max_headers {
                break;
            }

            let value_str = match value {
                StrOrBytes::Utf8(s) => s,
                StrOrBytes::Bytes(_bytes) => {
                    // Skip invalid UTF-8 headers for now
                    continue;
                }
            };

            if value_str.len() > self.config.max_header_value_size {
                continue; // Skip oversized headers
            }

            if total_size + name.len() + value_str.len() > self.config.max_total_header_size {
                break; // Stop if total size would exceed limit
            }

            let key = WsString::new(ws, &name.to_lowercase())?;
            let ws_value = WsString::new(ws, value_str)?;

            // Handle multi-value headers by combining with comma separation (RFC 7230)
            if let Some(existing) = headers.get(&name.to_lowercase()) {
                let combined = format!("{}, {}", existing.as_str(), value_str);
                let combined_ws = WsString::new(ws, &combined)?;
                headers.insert(key, combined_ws)?;
            } else {
                headers.insert(key, ws_value)?;
            }

            header_count += 1;
            total_size += name.len() + value_str.len();
        }

        Ok((headers, header_count, total_size))
    }


    /// Extract client IP from various sources using workspace
    fn extract_client_ip_ws<'ctx>(&self, ws: &mut Workspace<'ctx>, req: &varnish::vcl::HttpHeaders) -> Result<Option<WsString<'ctx>>, VclError> {
        // Priority order for IP extraction:
        // 1. X-Forwarded-For (first IP if comma-separated)
        // 2. X-Real-IP
        // 3. X-Client-IP

        if let Some(xff) = req.header("x-forwarded-for") {
            let xff_str = match xff {
                StrOrBytes::Utf8(s) => s,
                StrOrBytes::Bytes(_) => return Ok(None), // Skip invalid UTF-8
            };
            // Take first IP from comma-separated list
            if let Some(first_ip) = xff_str.split(',').next() {
                return Ok(Some(WsString::new(ws, first_ip.trim())?));
            }
        }

        if let Some(real_ip) = req.header("x-real-ip") {
            let real_ip_str = match real_ip {
                StrOrBytes::Utf8(s) => s,
                StrOrBytes::Bytes(_) => return Ok(None),
            };
            return Ok(Some(WsString::new(ws, real_ip_str)?));
        }

        if let Some(client_ip) = req.header("x-client-ip") {
            let client_ip_str = match client_ip {
                StrOrBytes::Utf8(s) => s,
                StrOrBytes::Bytes(_) => return Ok(None),
            };
            return Ok(Some(WsString::new(ws, client_ip_str)?));
        }

        Ok(None)
    }


    /// Extract and parse cookies with safety limits using workspace
    fn extract_cookies_ws<'ctx>(
        &self,
        ws: &mut Workspace<'ctx>,
        req: &varnish::vcl::HttpHeaders,
    ) -> Result<Option<WsHashMap<'ctx>>, VclError> {
        let cookie_header = match req.header("cookie") {
            Some(cookies) => match cookies {
                StrOrBytes::Utf8(s) => s,
                StrOrBytes::Bytes(_) => return Ok(None), // Skip invalid UTF-8
            },
            None => return Ok(None),
        };

        let mut cookies = WsHashMap::new(ws, self.config.max_cookie_count)?;
        let mut cookie_count = 0;

        for cookie_pair in cookie_header.split(';') {
            if cookie_count >= self.config.max_cookie_count {
                break;
            }

            let cookie_pair = cookie_pair.trim();
            if let Some(eq_pos) = cookie_pair.find('=') {
                let name = cookie_pair[..eq_pos].trim();
                let value = cookie_pair[eq_pos + 1..].trim();

                // Basic cookie value unquoting
                let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                    &value[1..value.len() - 1]
                } else {
                    value
                };

                let ws_name = WsString::new(ws, name)?;
                let ws_value = WsString::new(ws, value)?;
                cookies.insert(ws_name, ws_value)?;
                cookie_count += 1;
            }
        }

        Ok(if cookies.is_empty() {
            None
        } else {
            Some(cookies)
        })
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_config_defaults() {
        let config = AttributeConfig::default();
        assert!(!config.extract_cookies);
        assert_eq!(config.max_headers, 50);
        assert_eq!(config.max_header_value_size, 8192);
        assert_eq!(config.max_cookie_count, 20);
    }

    // Note: Tests for WsRequestAttrs and workspace-based extraction
    // require a Varnish context and are better handled in integration tests
    // or VTC (Varnish Test Case) tests where a real Varnish workspace is available.
}
