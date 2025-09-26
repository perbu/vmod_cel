vcl 4.1;

# Example VCL configuration demonstrating simplified vmod_cel usage
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

# Initialize CEL module and load rules
sub vcl_init {
    # Initialize the CEL module
    if (!cel.init()) {
        std.log("Failed to initialize CEL module");
        return;
    }

    # Load rule sets - combine multiple rule files
    # Start with basic rules for initial deployment
    if (!cel.load_file("/etc/varnish/rules/basic_rules.yaml")) {
        std.log("Failed to load basic rules");
    }

    # Add medium complexity rules for API protection
    if (!cel.load_file("/etc/varnish/rules/medium_rules.yaml")) {
        std.log("Failed to load medium rules");
    }

    # Configure attribute extraction
    if (!cel.configure_attributes(
        true,    # extract_cookies
        100,     # max_headers
        8192     # max_header_size
    )) {
        std.log("Failed to configure CEL attributes");
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

    # Basic health check bypass - allow before security rules
    if (req.url == "/health" || req.url == "/ping") {
        std.log("Health check allowed, bypassing CEL rules");
        return (pass);
    }

    # Evaluate all security rules - block if ANY rule matches (logical OR)
    # This includes bot blocking, method validation, admin protection, etc.
    if (cel.eval_any(ctx)) {
        std.log("CEL: Request blocked by security rules from " + req.http.X-Real-IP);
        std.syslog(LOG_WARNING, "CEL blocked request from " + req.http.X-Real-IP +
                   ": " + req.method + " " + req.url);
        return (synth(403, "Request blocked by security policy"));
    }

    # Alternative approach: Use eval_all() for rules that ALL must pass
    # This would be useful for validation rules where everything must be valid
    # if (!cel.eval_all(ctx)) {
    #     std.log("CEL: Request failed validation rules from " + req.http.X-Real-IP);
    #     return (synth(400, "Request failed validation"));
    # }

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
    # Add monitoring headers (remove in production for security)
    set resp.http.X-CEL-Metrics = cel.metrics_summary();
    set resp.http.X-CEL-Safety = cel.safety_status();

    # For production, remove debug headers:
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

    if (resp.status == 400) {
        set resp.http.Content-Type = "text/html; charset=utf-8";
        set resp.http.Retry-After = "60";

        synthetic({"
<!DOCTYPE html>
<html>
<head>
    <title>Bad Request</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .error { color: #d32f2f; }
    </style>
</head>
<body>
    <h1 class="error">Bad Request</h1>
    <p>Your request could not be processed due to validation errors.</p>
    <p>Please check your request and try again.</p>
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