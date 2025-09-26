# CEL Rules Examples

This directory contains example rulesets demonstrating the capabilities of the vmod_cel CEL expression evaluation module for Varnish Cache.

## Example Files

### Basic Rules (`basic_rules.yaml` / `basic_rules.json`)

**Complexity Level**: Beginner
**Use Case**: Simple security policies and common filtering scenarios

These rules demonstrate:
- Basic HTTP method filtering
- Simple header validation
- Bot detection with regex patterns
- Path-based access control
- Network-based restrictions using CIDR matching

Perfect for:
- Small websites and applications
- Basic security hardening
- Learning CEL syntax
- Quick deployment scenarios

### Medium Rules (`medium_rules.yaml`)

**Complexity Level**: Intermediate
**Use Case**: API security and moderate threat detection

These rules demonstrate:
- Multi-condition logic with AND/OR operators
- API-specific security patterns
- Content-type validation
- Time-based access controls
- File upload security
- Basic attack pattern detection (XSS, SQL injection)
- API version management

Perfect for:
- REST APIs and web services
- Medium-sized applications
- Organizations with moderate security requirements
- Development and staging environments

### Complex Rules (`complex_rules.yaml`)

**Complexity Level**: Advanced
**Use Case**: Enterprise-grade security with sophisticated threat detection

These rules demonstrate:
- Multi-vector attack detection
- Behavioral analysis patterns
- Geographic and temporal anomaly detection
- Advanced injection attack detection
- Machine learning evasion detection
- Zero-day exploit pattern recognition
- Business logic abuse prevention
- Content Security Policy bypass detection
- Advanced Persistent Threat (APT) indicators

Perfect for:
- Large enterprise applications
- High-security environments
- Organizations with advanced threat actors
- Production systems requiring comprehensive protection

## Rule Structure

All rules follow the same basic structure:

```yaml
metadata:
  name: "ruleset_name"
  description: "Description of the ruleset"
  version: "1.0.0"
  author: "Author information"

rules:
  - name: "rule_name"
    description: "What this rule does"
    expression: 'CEL expression to evaluate'
    enabled: true
    tags: ["category", "type"]
```

## Available CEL Functions

The following functions are available in CEL expressions:

### Request Context
- `request.method` - HTTP method (GET, POST, etc.)
- `request.path` - Request path
- `request.query` - Query parameters
- `request.user_agent` - User-Agent header value
- `client_ip()` - Client IP address

### Header Functions
- `has_header("Header-Name")` - Check if header exists
- `request.headers.get("header-name", "default")` - Get header value

### Network Functions
- `in_cidr(ip, "192.168.0.0/16")` - Check if IP is in CIDR range

### String Functions
- `size(string)` - Get string length
- `string.startsWith("prefix")` - Check string prefix
- `string.contains("substring")` - Check if string contains substring
- `string.matches("regex")` - Regular expression matching

### Utility Functions
- `timestamp()` - Current Unix timestamp
- `int(value)` - Convert to integer

## Usage in VCL

Load rules from files:

```vcl
sub vcl_init {
    cel.init();
    cel.load_file("/path/to/rules.yaml");
}

sub vcl_recv {
    if (cel.eval("block_bots")) {
        return (synth(403, "Blocked"));
    }

    if (!cel.eval_or("allowed_methods", true)) {
        return (synth(405, "Method Not Allowed"));
    }
}
```

## Testing Rules

Add rules dynamically for testing:

```vcl
sub vcl_init {
    cel.init();
    cel.add_rule("test_rule", 'request.method == "GET"');
}
```

## Performance Considerations

- **Basic rules**: ~5-15μs per evaluation
- **Medium rules**: ~20-50μs per evaluation
- **Complex rules**: ~50-200μs per evaluation

Use `cel.metrics_summary()` to monitor performance in production.

## Security Notes

- Always test rules in a staging environment first
- Some complex rules may have false positives - monitor and tune
- Rules marked with `enabled: false` require careful evaluation before activation
- Consider the performance impact of regex-heavy rules
- Review and update rules regularly as attack patterns evolve

## Contributing

When creating new example rules:

1. Use clear, descriptive names and descriptions
2. Include relevant tags for categorization
3. Test thoroughly before submitting
4. Document any performance implications
5. Consider false positive scenarios
6. Follow CEL best practices for readability