vcl 4.1;

# Example VCL configuration demonstrating vmod_cel usage
# This example shows how to integrate CEL rules with Varnish Cache
# for advanced request filtering and security policies

import std;
import cel;

# Backend configuration
backend default {
    .host = "127.0.0.1";
    .port = "8080";
    .connect_timeout = 5s;
    .first_byte_timeout = 30s;
    .between_bytes_timeout = 10s;
}

# Backend for blocked requests (optional - can use synth instead)
backend blackhole {
    .host = "127.0.0.1";
    .port = "9999";  # Non-existent port
    .connect_timeout = 1s;
    .first_byte_timeout = 1s;
}

# Initialize CEL module and load rules
sub vcl_init {
    # Initialize the CEL module
    if (!cel.init()) {
        return;
    }

    # Load rule sets - choose one or combine multiple
    # Start with basic rules for initial deployment
    if (!cel.load_file("/etc/varnish/rules/basic_rules.yaml")) {
        std.log("Failed to load basic rules");
    }

    # Add medium complexity rules for API protection
    # if (!cel.load_file("/etc/varnish/rules/medium_rules.yaml")) {
    #     std.log("Failed to load medium rules");
    # }

    # Add complex rules for enterprise security (careful - may cause false positives)
    # if (!cel.load_file("/etc/varnish/rules/complex_rules.yaml")) {
    #     std.log("Failed to load complex rules");
    # }

    # Configure attribute extraction
    if (!cel.configure_attributes(
        true,    # extract_cookies
        100,     # max_headers
        8192     # max_header_size
    )) {
        std.log("Failed to configure CEL attributes");
    }

    # Enable explanation mode for debugging (disable in production)
    if (!cel.set_explain_mode(true)) {
        std.log("Failed to enable CEL explain mode");
    }

    # Add some dynamic rules for testing
    if (!cel.add_rule("block_curl", 'request.user_agent.contains("curl")')) {
        std.log("Failed to add curl blocking rule");
    }

    std.log("CEL module initialized successfully");
}

# Main request processing logic
sub vcl_recv {
    # Set client IP from X-Forwarded-For if behind a proxy
    if (req.http.X-Forwarded-For) {
        set req.http.X-Real-IP = regsub(req.http.X-Forwarded-For, ",.*", "");
    } else {
        set req.http.X-Real-IP = client.ip;
    }

    # Basic security rules - block immediately on match
    if (cel.eval("block_bots")) {
        std.log("CEL: Blocked bot - " + cel.explain("block_bots"));
        return (synth(403, "Bot traffic not allowed"));
    }

    # Method validation - only allow specific methods
    if (!cel.eval_or("allowed_methods", true)) {
        std.log("CEL: Blocked method " + req.method + " - " + cel.explain("allowed_methods"));
        return (synth(405, "Method not allowed"));
    }

    # Require User-Agent header
    if (!cel.eval("require_user_agent")) {
        std.log("CEL: Missing User-Agent - " + cel.explain("require_user_agent"));
        return (synth(400, "User-Agent header required"));
    }

    # Always allow health checks (bypass other rules)
    if (cel.eval("allow_health_check")) {
        std.log("CEL: Health check allowed");
        # Skip cache for health checks
        return (pass);
    }

    # Protect admin areas
    if (cel.eval("protect_admin")) {
        std.log("CEL: Admin area blocked for " + req.http.X-Real-IP + " - " + cel.explain("protect_admin"));
        return (synth(403, "Access denied"));
    }

    # API-specific rules (if medium rules are loaded)
    # API authentication check
    if (cel.eval_or("api_auth_required", false)) {
        std.log("CEL: API authentication required - " + cel.explain("api_auth_required"));
        return (synth(401, "Authentication required"));
    }

    # Suspicious activity detection
    if (cel.eval_or("suspicious_activity", false)) {
        std.log("CEL: Suspicious activity detected - " + cel.explain("suspicious_activity"));
        # Log to security system
        std.syslog(LOG_WARNING, "Suspicious activity from " + req.http.X-Real-IP +
                   ": " + req.method + " " + req.url);
        return (synth(429, "Rate limited"));
    }

    # Content type validation for API endpoints
    if (cel.eval_or("api_content_type_validation", false)) {
        std.log("CEL: Invalid content type - " + cel.explain("api_content_type_validation"));
        return (synth(415, "Unsupported Media Type"));
    }

    # File upload security
    if (cel.eval_or("file_upload_validation", false)) {
        std.log("CEL: Dangerous file upload blocked - " + cel.explain("file_upload_validation"));
        return (synth(400, "File type not allowed"));
    }

    # Block deprecated API versions
    if (cel.eval_or("deprecated_api_version", false)) {
        std.log("CEL: Deprecated API version - " + cel.explain("deprecated_api_version"));
        return (synth(410, "API version deprecated"));
    }

    # XSS detection in query parameters
    if (cel.eval_or("xss_in_query_params", false)) {
        std.log("CEL: XSS attempt blocked - " + cel.explain("xss_in_query_params"));
        std.syslog(LOG_ALERT, "XSS attempt from " + req.http.X-Real-IP +
                   ": " + req.url);
        return (synth(400, "Malicious request blocked"));
    }

    # SQL injection detection
    if (cel.eval_or("sql_injection_attempt", false)) {
        std.log("CEL: SQL injection attempt blocked - " + cel.explain("sql_injection_attempt"));
        std.syslog(LOG_ALERT, "SQL injection attempt from " + req.http.X-Real-IP +
                   ": " + req.url);
        return (synth(400, "Malicious request blocked"));
    }

    # Complex rules (enterprise-grade - enable carefully)
    # Advanced threat detection
    if (cel.eval_or("advanced_threat_detection", false)) {
        std.log("CEL: Advanced threat detected - " + cel.explain("advanced_threat_detection"));
        std.syslog(LOG_CRIT, "Advanced threat from " + req.http.X-Real-IP +
                   ": " + req.method + " " + req.url);
        # Could redirect to CAPTCHA or rate limiting service
        return (synth(403, "Advanced security check required"));
    }

    # API abuse detection
    if (cel.eval_or("api_abuse_behavioral_analysis", false)) {
        std.log("CEL: API abuse detected - " + cel.explain("api_abuse_behavioral_analysis"));
        return (synth(429, "API usage limit exceeded"));
    }

    # Geographic anomaly detection
    if (cel.eval_or("geo_temporal_anomaly", false)) {
        std.log("CEL: Geographic anomaly - " + cel.explain("geo_temporal_anomaly"));
        # Could trigger 2FA requirement
        return (synth(403, "Geographic verification required"));
    }

    # Business logic abuse
    if (cel.eval_or("business_logic_abuse", false)) {
        std.log("CEL: Business logic abuse - " + cel.explain("business_logic_abuse"));
        std.syslog(LOG_ALERT, "Business logic abuse from " + req.http.X-Real-IP +
                   ": " + req.url);
        return (synth(400, "Invalid request"));
    }

    # Add custom headers for downstream applications
    set req.http.X-CEL-Processed = "true";
    set req.http.X-CEL-Timestamp = std.time2integer(now, 0);

    # Cache control for different content types
    if (req.url ~ "^/api/") {
        # Don't cache API responses by default
        return (pass);
    } else if (req.url ~ "\.(css|js|png|jpg|jpeg|gif|ico|svg|woff2?)$") {
        # Cache static assets
        unset req.http.Cookie;
        return (hash);
    }

    # Default processing
    return (hash);
}

# Handle cache hits
sub vcl_hit {
    # Log cache hit with CEL info
    std.log("Cache HIT: " + req.url + " (CEL processed)");
    return (deliver);
}

# Handle cache misses
sub vcl_miss {
    std.log("Cache MISS: " + req.url + " (CEL processed)");
    return (fetch);
}

# Backend response processing
sub vcl_backend_response {
    # Set caching headers based on content type
    if (beresp.http.Content-Type ~ "text/html") {
        set beresp.ttl = 1h;
        set beresp.grace = 30s;
    } else if (beresp.http.Content-Type ~ "(css|javascript)") {
        set beresp.ttl = 1d;
        set beresp.grace = 4h;
    } else if (beresp.http.Content-Type ~ "image/") {
        set beresp.ttl = 1w;
        set beresp.grace = 1d;
    }

    # Add security headers
    set beresp.http.X-Content-Type-Options = "nosniff";
    set beresp.http.X-Frame-Options = "DENY";
    set beresp.http.X-XSS-Protection = "1; mode=block";

    return (deliver);
}

# Client response processing
sub vcl_deliver {
    # Add performance and security headers
    set resp.http.X-CEL-Rules = cel.list_rules();
    set resp.http.X-CEL-Metrics = cel.metrics_summary();
    set resp.http.X-CEL-Safety = cel.safety_status();

    # Remove sensitive headers in production
    # unset resp.http.X-CEL-Rules;
    # unset resp.http.X-CEL-Metrics;
    # unset resp.http.X-CEL-Safety;

    # Add cache status
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
        set resp.http.X-Cache-Hits = obj.hits;
    } else {
        set resp.http.X-Cache = "MISS";
    }

    return (deliver);
}

# Error handling
sub vcl_synth {
    # Custom error pages for security blocks
    if (resp.status == 403) {
        set resp.http.Content-Type = "text/html; charset=utf-8";
        set resp.http.Retry-After = "120";

        synthetic({"
<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .error { color: #d32f2f; }
        .details { margin-top: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <h1 class="error">Access Denied</h1>
    <p>Your request has been blocked by our security system.</p>
    <p>If you believe this is an error, please contact support.</p>
    <div class="details">
        <p>Reference: "} + req.http.X-Request-ID + {"</p>
        <p>Time: "} + std.time2iso(now, 0) + {"</p>
    </div>
</body>
</html>
        "});

        return (deliver);
    }

    if (resp.status == 429) {
        set resp.http.Content-Type = "text/html; charset=utf-8";
        set resp.http.Retry-After = "300";

        synthetic({"
<!DOCTYPE html>
<html>
<head>
    <title>Rate Limited</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .error { color: #f57c00; }
    </style>
</head>
<body>
    <h1 class="error">Rate Limited</h1>
    <p>You are making requests too quickly. Please slow down.</p>
    <p>Try again in 5 minutes.</p>
</body>
</html>
        "});

        return (deliver);
    }

    # Default error handling
    return (deliver);
}

# Logging and monitoring
sub vcl_log {
    # Log CEL metrics periodically
    std.log("CEL Metrics: " + cel.metrics_summary());
    std.log("CEL Safety: " + cel.safety_status());
}

# Cleanup on VCL unload
sub vcl_fini {
    std.log("CEL VCL configuration unloaded");
}