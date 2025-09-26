# VMOD CEL Versioning Policy

This document describes the semantic versioning policy for the VMOD CEL project.

## Semantic Versioning

We follow [Semantic Versioning 2.0.0](https://semver.org/) for all releases:

- **MAJOR version** (X.y.z): Incompatible API changes
- **MINOR version** (x.Y.z): Backwards-compatible functionality additions
- **PATCH version** (x.y.Z): Backwards-compatible bug fixes

## VMOD API Compatibility

### Major Version Changes (Breaking Changes)

Major version increments occur when:

1. **VCL Function Signatures Change**
   - Parameter types or order changes
   - Return type changes
   - Function removal

2. **VCL Function Behavior Changes**
   - Semantic changes that could break existing VCL logic
   - Error handling changes that affect control flow

3. **Configuration Format Changes**
   - YAML/JSON schema breaking changes
   - Required field additions
   - Field type changes

4. **Runtime Requirements Changes**
   - Minimum Varnish version increases (major version)
   - Required system dependencies changes

### Minor Version Changes (Backwards-Compatible Additions)

Minor version increments occur when:

1. **New VCL Functions**
   - Adding new `cel.*()` functions
   - Adding new optional parameters (with defaults)

2. **New Configuration Options**
   - Adding optional configuration fields
   - Adding new rule validation features

3. **Performance Improvements**
   - Optimizations that don't change behavior
   - New benchmarks or metrics

4. **Extended Support**
   - Support for new Varnish versions (minor/patch)
   - Support for new Linux distributions

### Patch Version Changes (Bug Fixes)

Patch version increments occur when:

1. **Bug Fixes**
   - Fixing incorrect evaluation results
   - Memory leak fixes
   - Thread safety fixes

2. **Documentation Updates**
   - README, examples, or inline documentation
   - Performance guide updates

3. **Build System Improvements**
   - CI/CD improvements
   - Dependency updates (patch versions only)

## Shared Library Versioning

The shared library (`libvmod_cel.so`) follows these conventions:

- **SONAME**: `libvmod_cel.so.{MAJOR}`
- **Real name**: `libvmod_cel.so.{MAJOR}.{MINOR}.{PATCH}`
- **Link name**: `libvmod_cel.so`

Examples:
- Version 0.1.0: `libvmod_cel.so.0.1.0` (SONAME: `libvmod_cel.so.0`)
- Version 0.2.5: `libvmod_cel.so.0.2.5` (SONAME: `libvmod_cel.so.0`)
- Version 1.0.0: `libvmod_cel.so.1.0.0` (SONAME: `libvmod_cel.so.1`)

## Symbol Visibility

Only essential VMOD symbols are exported:
- `Vmod_cel_Data`
- `Vmod_cel_Func`
- `vmod_*` prefixed functions

All internal symbols are hidden to:
- Reduce binary size
- Prevent symbol conflicts
- Improve security

## Release Process

### Version Numbering

1. **Development versions**: Use `-dev` suffix (e.g., `0.2.0-dev`)
2. **Release candidates**: Use `-rc.N` suffix (e.g., `0.2.0-rc.1`)
3. **Stable releases**: No suffix (e.g., `0.2.0`)

### Compatibility Testing

Before any release:
1. Run full test suite against all supported Varnish versions
2. Verify VCL compatibility with existing configurations
3. Validate shared library compatibility
4. Check for symbol visibility regressions

### Communication

- **Major releases**: Announce with migration guide
- **Minor releases**: Announce with feature highlights
- **Patch releases**: Can be announced in batch

## Deprecation Policy

For major version changes requiring breaking changes:

1. **Deprecation Notice** (Minor version)
   - Mark functions/features as deprecated
   - Add warnings to logs when deprecated features are used
   - Document migration path

2. **Deprecation Period** (Minimum 6 months)
   - Continue supporting deprecated features
   - Provide clear migration documentation
   - Update examples to use new APIs

3. **Removal** (Major version)
   - Remove deprecated functionality
   - Update version compatibility matrix
   - Provide automated migration tools where possible

## Version Compatibility Matrix

| VMOD CEL Version | Varnish Support | Status |
|------------------|-----------------|---------|
| 0.1.x | 7.2, 7.3, 7.4 | Active Development |

This matrix will be updated with each release.

## Examples

### VCL Function Addition (Minor)
```vcl
# Version 0.1.0 - existing function
if (cel.eval("rule_name")) { ... }

# Version 0.2.0 - add new function (backwards compatible)
if (cel.eval_with_timeout("rule_name", 100ms)) { ... }
```

### VCL Function Change (Major)
```vcl
# Version 0.x.x - returns BOOL
if (cel.eval("rule_name")) { ... }

# Version 1.0.0 - returns STRING with details (breaking change)
if (cel.eval("rule_name") == "ALLOW") { ... }
```

### Configuration Addition (Minor)
```yaml
# Version 0.1.0
version: 1
rules:
  - name: test
    expr: "true"

# Version 0.2.0 - add optional timeout (backwards compatible)
version: 1
rules:
  - name: test
    expr: "true"
    timeout: "100ms"  # optional
```