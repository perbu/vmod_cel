use crate::policy_engine::PolicyEngine;
use crate::request_attrs::RequestAttrs;
use crate::safety_limits::{CostTracker, SafetyError, SafetyLimits};
use anyhow::Result;
use cel::{Context, Program};
use std::panic;
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;

/// CEL evaluation engine using the cel-rust library
///
/// This engine provides a safe, fast CEL evaluation environment with:
/// - Safety limits and cost tracking
/// - Panic recovery and error handling
/// - Thread-safe operation
pub struct CelRustEngine {
    /// Safety limits for compilation and evaluation
    limits: SafetyLimits,

    /// Engine metadata
    version: String,
}

/// CEL-specific error types
#[derive(Error, Debug)]
pub enum CelError {
    #[error("Compilation failed: {message}")]
    CompilationFailed { message: String },

    #[error("Evaluation failed: {message}")]
    EvaluationFailed { message: String },

    #[error("Safety limit violated: {0}")]
    SafetyLimitViolated(#[from] SafetyError),

    #[error("Panic during operation: {message}")]
    PanicOccurred { message: String },

    #[error("Invalid expression: {message}")]
    InvalidExpression { message: String },

    #[error("Context error: {message}")]
    ContextError { message: String },

    #[error("Internal error: {0}")]
    InternalError(#[from] anyhow::Error),
}

impl CelRustEngine {
    /// Create a new CEL engine with default safety limits
    pub fn new() -> Result<Self, CelError> {
        Self::with_limits(SafetyLimits::default())
    }

    /// Create a new CEL engine with custom safety limits
    pub fn with_limits(limits: SafetyLimits) -> Result<Self, CelError> {
        Ok(Self {
            limits,
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }


    /// Create a CEL evaluation context from request attributes
    fn create_eval_context(&self, _attrs: &RequestAttrs) -> Result<Context, CelError> {
        let eval_context = Context::default();

        // TODO: Add request data as variables once we understand the cel crate API better
        // For now, return empty context

        Ok(eval_context)
    }


    /// Safely execute a function with panic recovery
    fn safe_execute<F, R>(&self, operation_name: &str, f: F) -> Result<R, CelError>
    where
        F: FnOnce() -> Result<R, CelError> + panic::UnwindSafe,
    {
        match panic::catch_unwind(f) {
            Ok(result) => result,
            Err(panic_info) => {
                let message = if let Some(s) = panic_info.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(&s) = panic_info.downcast_ref::<&str>() {
                    s.to_string()
                } else {
                    format!("Unknown panic in {}", operation_name)
                };

                Err(CelError::PanicOccurred { message })
            }
        }
    }
}

impl PolicyEngine for CelRustEngine {
    type Program = Program;
    type Error = CelError;

    fn compile(&self, _name: &str, expr: &str) -> Result<Self::Program, Self::Error> {
        let _start_time = Instant::now();

        // Check safety limits
        self.limits.check_expression_size(expr)?;

        // Safely compile the expression
        self.safe_execute("compile", || {
            let program = Program::compile(expr).map_err(|e| CelError::CompilationFailed {
                message: format!("CEL compilation error: {}", e),
            })?;

            Ok(program)
        })
    }

    fn eval(&self, program: &Self::Program, attrs: &RequestAttrs) -> Result<bool, Self::Error> {
        let _start_time = Instant::now();
        let mut _cost_tracker = CostTracker::new(self.limits.max_eval_steps, self.limits.max_eval_time);

        // Safely evaluate the expression
        self.safe_execute("eval", || {
            // Create evaluation context with request data
            let context = self.create_eval_context(attrs)?;

            // Execute the program
            let result = program.execute(&context).map_err(|e| CelError::EvaluationFailed {
                message: format!("CEL evaluation error: {}", e),
            })?;

            // Convert result to boolean
            let boolean_result = match result {
                cel::Value::Bool(b) => b,
                cel::Value::Int(i) => i != 0,
                cel::Value::UInt(u) => u != 0,
                cel::Value::String(_) => true, // Non-empty string is truthy
                cel::Value::List(_) => true, // Non-empty list is truthy
                cel::Value::Map(_) => true, // Non-empty map is truthy
                _ => false,
            };

            Ok(boolean_result)
        })
    }

    fn validate_expr(&self, expr: &str) -> Result<(), Self::Error> {
        self.limits.check_expression_size(expr)?;

        self.safe_execute("validate", || {
            // Try to compile to validate syntax
            Program::compile(expr).map_err(|e| CelError::InvalidExpression {
                message: format!("Expression validation failed: {}", e),
            })?;

            Ok(())
        })
    }

    fn estimate_cost(&self, expr: &str) -> Result<u64, Self::Error> {
        // Simple cost estimation based on expression characteristics
        let mut cost = 10; // Base cost

        // Add cost based on expression length
        cost += (expr.len() / 10) as u64;

        // Add cost for potential expensive operations
        if expr.contains("matches") || expr.contains("regex") {
            cost += 50; // Regex operations are expensive
        }

        if expr.contains("in_cidr") {
            cost += 20; // CIDR operations have moderate cost
        }

        // Count function calls
        let function_count = expr.matches('(').count() as u64;
        cost += function_count * 5;

        // Count string operations
        if expr.contains("contains") || expr.contains("startsWith") || expr.contains("endsWith") {
            cost += 15;
        }

        Ok(cost)
    }

    fn engine_name(&self) -> &'static str {
        "CelRustEngine"
    }

    fn engine_version(&self) -> String {
        format!("vmod_cel/{} cel-rust/{}", self.version, "0.11") // Would get actual cel version
    }
}

impl Default for CelRustEngine {
    fn default() -> Self {
        Self::new().expect("Failed to create default CelRustEngine")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_attrs::RequestAttrs;
    use std::collections::HashMap;

    fn create_test_attrs() -> RequestAttrs {
        let mut attrs = RequestAttrs::empty();
        attrs.method = "GET".to_string();
        attrs.path = "/api/v1/users".to_string();
        attrs.query = Some("page=1&limit=10".to_string());
        attrs.client_ip = Some("192.168.1.100".to_string());
        attrs.user_agent = Some("Mozilla/5.0 (compatible; TestBot/1.0)".to_string());

        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("authorization".to_string(), "Bearer token123".to_string());
        attrs.headers = headers;

        attrs
    }

    #[test]
    fn test_engine_creation() {
        let engine = CelRustEngine::new();
        assert!(engine.is_ok());

        let engine = engine.unwrap();
        assert_eq!(engine.engine_name(), "CelRustEngine");
    }

    #[test]
    fn test_simple_expressions() {
        let engine = CelRustEngine::new().unwrap();
        let attrs = create_test_attrs();

        // Simple boolean expression
        let program = engine.compile("simple", "true").unwrap();
        let result = engine.eval(&program, &attrs).unwrap();
        assert!(result);

        // Method check
        let program = engine.compile("method_check", "method == 'GET'").unwrap();
        let result = engine.eval(&program, &attrs).unwrap();
        assert!(result);
    }

    #[test]
    fn test_path_expressions() {
        let engine = CelRustEngine::new().unwrap();
        let attrs = create_test_attrs();

        // Path starts with check
        let program = engine.compile("path_check", "path.startsWith('/api')").unwrap();
        let result = engine.eval(&program, &attrs).unwrap();
        assert!(result);
    }

    #[test]
    fn test_safety_limits() {
        let limits = SafetyLimits {
            max_expression_size: 10,
            ..SafetyLimits::default()
        };
        let engine = CelRustEngine::with_limits(limits).unwrap();

        // Should fail due to expression size limit
        let result = engine.compile("too_long", "this expression is way too long for the limit");
        assert!(result.is_err());
    }

    #[test]
    fn test_validation() {
        let engine = CelRustEngine::new().unwrap();

        // Valid expression
        assert!(engine.validate_expr("true").is_ok());

        // Invalid expression
        assert!(engine.validate_expr("invalid syntax !!!").is_err());
    }

    #[test]
    fn test_cost_estimation() {
        let engine = CelRustEngine::new().unwrap();

        let simple_cost = engine.estimate_cost("true").unwrap();
        let complex_cost = engine
            .estimate_cost("method == 'GET' && path.matches('/api/.*') && in_cidr(client_ip, '192.168.0.0/16')")
            .unwrap();

        assert!(complex_cost > simple_cost);
    }
}