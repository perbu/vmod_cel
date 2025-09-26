# VCL Cookbook: CEL VMOD Usage Patterns

This cookbook provides practical examples and common patterns for using the CEL VMOD in Varnish VCL configurations.

## Table of Contents

1. [Basic Setup](#basic-setup)
2. [Rule Evaluation Patterns](#rule-evaluation-patterns)
3. [Error Handling & Graceful Degradation](#error-handling--graceful-degradation)
4. [Debugging & Development](#debugging--development)
5. [Common Use Cases](#common-use-cases)
6. [Performance Best Practices](#performance-best-practices)

## Basic Setup

### Minimal VCL Configuration

```vcl
vcl 4.1;
import cel;

sub vcl_init {
    cel.init();
    cel.load_file("/etc/varnish/cel_rules.yaml");
}

sub vcl_recv {
    if (cel.eval("block_scanners")) {
        return (synth(403, "Forbidden"));
    }
}
```

### Development vs Production Setup

```vcl
sub vcl_init {
    cel.init();
    cel.load_file("/etc/varnish/cel_rules.yaml");

    # Enable debug mode in development
    if (std.getenv("ENVIRONMENT") == "development") {
        cel.set_explain_mode(true);
    } else {
        cel.set_explain_mode(false);
    }
}
```

## Rule Evaluation Patterns

### Basic Rule Evaluation

```vcl
sub vcl_recv {
    # Block known bad actors
    if (cel.eval("block_scanners")) {
        return (synth(403, "Scanner Blocked"));
    }

    # Rate limiting check
    if (cel.eval("rate_limit_exceeded")) {
        return (synth(429, "Rate Limited"));
    }
}
```

### Graceful Degradation with eval_or

```vcl
sub vcl_recv {
    # Use eval_or for optional rules that might not exist
    if (cel.eval_or("experimental_blocking", false)) {
        return (synth(403, "Experimental Block"));
    }

    # Default to allowing if rule fails or doesn't exist
    if (cel.eval_or("allow_admin_access", true)) {
        # Continue processing
    } else {
        return (synth(403, "Admin Access Denied"));
    }
}
```

## Error Handling & Graceful Degradation

### Safe Rule Loading

```vcl
sub vcl_init {
    cel.init();

    # Primary rules file
    if (cel.load_file("/etc/varnish/cel_rules.yaml") != 0) {
        # Fallback to backup rules if primary fails
        cel.load_file("/etc/varnish/cel_rules_backup.yaml");
    }
}
```

### Combining eval() and eval_or()

```vcl
sub vcl_recv {
    # Critical security rules - fail closed
    if (cel.eval("critical_security_check")) {
        return (synth(403, "Security Violation"));
    }

    # Optional enhancement rules - fail open
    if (cel.eval_or("performance_optimization", false)) {
        # Apply performance optimizations
        set req.http.X-Optimized = "true";
    }
}
```

## Debugging & Development

### Debug Headers in Development

```vcl
sub vcl_deliver {
    # Add debug information when explain mode is enabled
    if (req.http.X-Debug-CEL) {
        set resp.http.X-CEL-Scanner-Check = cel.explain("block_scanners");
        set resp.http.X-CEL-Rate-Limit = cel.explain("rate_limit_check");
    }
}
```

### Conditional Debug Output

```vcl
sub vcl_recv {
    # Debug mode controlled by header
    if (req.http.X-Debug == "cel" && client.ip ~ debug_ips) {
        set req.http.X-Debug-CEL = "1";
    }
}

sub vcl_deliver {
    if (req.http.X-Debug-CEL) {
        # Add explanation for each rule evaluated
        set resp.http.X-CEL-Explain-Scanner = cel.explain("block_scanners");
        set resp.http.X-CEL-Explain-Ratelimit = cel.explain("rate_limit_check");

        # Remove debug header from response in production
        if (std.getenv("ENVIRONMENT") == "production") {
            unset resp.http.X-Debug-CEL;
        }
    }
}
```

## Common Use Cases

### IP Address Blocking

Example rules file (`/etc/varnish/cel_rules.yaml`):
```yaml
version: 1
rules:
  - name: block_known_bad_ips
    expr: 'in_cidr(request.client_ip, "192.0.2.0/24") || in_cidr(request.client_ip, "198.51.100.0/24")'
    description: "Block known malicious IP ranges"

  - name: allow_admin_ips
    expr: 'in_cidr(request.client_ip, "10.0.0.0/8") || in_cidr(request.client_ip, "172.16.0.0/12")'
    description: "Allow admin access from private networks"
```

VCL usage:
```vcl
sub vcl_recv {
    # Block bad IPs first
    if (cel.eval("block_known_bad_ips")) {
        return (synth(403, "IP Blocked"));
    }

    # Admin area protection
    if (req.url ~ "^/admin" && !cel.eval_or("allow_admin_ips", false)) {
        return (synth(403, "Admin Access Restricted"));
    }
}
```

### User Agent Filtering

Rules file:
```yaml
rules:
  - name: block_scanners
    expr: 'request.user_agent.matches("(?i)(sqlmap|nikto|nessus|masscan|nmap)")'
    description: "Block common security scanners"

  - name: allow_good_bots
    expr: 'request.user_agent.matches("(?i)(googlebot|bingbot|slurp)")'
    description: "Allow legitimate search engine bots"
```

VCL usage:
```vcl
sub vcl_recv {
    # Block scanners
    if (cel.eval("block_scanners")) {
        return (synth(403, "Scanner Detected"));
    }

    # Rate limit non-bot traffic
    if (!cel.eval_or("allow_good_bots", false) &&
        cel.eval_or("rate_limit_humans", false)) {
        return (synth(429, "Rate Limited"));
    }
}
```

### Path-Based Access Control

Rules file:
```yaml
rules:
  - name: block_sensitive_paths
    expr: 'request.path.matches("^/(admin|config|private|\.git|\.env)")'
    description: "Block access to sensitive paths"

  - name: api_key_required
    expr: 'request.path.startsWith("/api/") && !has_header("X-API-Key")'
    description: "Require API key for API endpoints"
```

VCL usage:
```vcl
sub vcl_recv {
    # Block sensitive paths
    if (cel.eval("block_sensitive_paths")) {
        return (synth(404, "Not Found"));
    }

    # API key validation
    if (cel.eval_or("api_key_required", false)) {
        return (synth(401, "API Key Required"));
    }
}
```

### Integration with Upstream Signals

Rules file:
```yaml
rules:
  - name: high_anomaly_score
    expr: 'has_header("X-Anomaly-Score") && int(header_value("X-Anomaly-Score")) > 80'
    description: "Block requests with high anomaly scores from upstream analysis"

  - name: fraud_detection_block
    expr: 'header_eq("X-Fraud-Risk", "high") || header_eq("X-Bot-Detection", "malicious")'
    description: "Block based on upstream fraud/bot detection"
```

VCL usage:
```vcl
sub vcl_recv {
    # Act on upstream analysis
    if (cel.eval_or("high_anomaly_score", false)) {
        return (synth(403, "Anomaly Detected"));
    }

    if (cel.eval_or("fraud_detection_block", false)) {
        return (synth(403, "Fraud Prevention"));
    }
}
```

## Performance Best Practices

### Rule Ordering

```vcl
sub vcl_recv {
    # Order rules by expected frequency and computational cost
    # 1. Fast IP-based checks first
    if (cel.eval("block_known_bad_ips")) {
        return (synth(403, "IP Blocked"));
    }

    # 2. Simple header checks
    if (cel.eval("missing_required_headers")) {
        return (synth(400, "Bad Request"));
    }

    # 3. Expensive regex checks last
    if (cel.eval("complex_user_agent_analysis")) {
        return (synth(403, "Blocked"));
    }
}
```

### Avoid Redundant Evaluations

```vcl
sub vcl_recv {
    # Store result for reuse instead of calling eval multiple times
    if (cel.eval("is_bot_traffic")) {
        set req.http.X-Is-Bot = "true";
    }
}

sub vcl_hash {
    if (req.http.X-Is-Bot == "true") {
        # Use stored result instead of re-evaluating
        hash_data("bot");
    }
}
```

### Conditional Rule Loading

```vcl
sub vcl_init {
    cel.init();

    # Load different rule sets based on environment
    if (std.getenv("ENVIRONMENT") == "production") {
        cel.load_file("/etc/varnish/rules_production.yaml");
    } else {
        cel.load_file("/etc/varnish/rules_development.yaml");
    }
}
```

### Monitoring and Metrics

```vcl
sub vcl_log {
    # Log CEL metrics for monitoring
    std.log("cel_metrics:" + cel.metrics_summary());
}

sub vcl_deliver {
    # Add performance headers for monitoring
    if (req.http.X-Debug-Performance) {
        set resp.http.X-CEL-Rules = cel.list_rules();
        set resp.http.X-CEL-Metrics = cel.metrics_summary();
    }
}
```

## Advanced Patterns

### Multi-Stage Evaluation

```vcl
sub vcl_recv {
    # Stage 1: Basic security checks
    if (cel.eval("basic_security_check")) {
        return (synth(403, "Basic Security Block"));
    }

    # Stage 2: Enhanced analysis (more expensive)
    if (cel.eval_or("enhanced_threat_detection", false)) {
        return (synth(403, "Advanced Threat Detected"));
    }
}

sub vcl_miss {
    # Stage 3: Backend-specific rules
    if (cel.eval_or("backend_protection_rules", false)) {
        return (synth(403, "Backend Protection"));
    }
}
```

### Rule Composition

```vcl
sub vcl_recv {
    # Combine multiple rules for complex logic
    set req.http.X-Security-Fail = "false";

    if (cel.eval("suspicious_ip") || cel.eval("suspicious_ua") || cel.eval("suspicious_path")) {
        set req.http.X-Security-Fail = "true";
    }

    if (req.http.X-Security-Fail == "true" && !cel.eval_or("whitelist_override", false)) {
        return (synth(403, "Multiple Security Indicators"));
    }
}
```