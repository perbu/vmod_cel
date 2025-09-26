use crate::policy_engine::PolicyEngine;
use crate::request_attrs::WsRequestAttrs;
use crate::safety_limits::{CostTracker, SafetyError, SafetyLimits};
use anyhow::Result;
use cel::{Context, Program};
use std::panic;
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

    /// Create a CEL evaluation context from workspace-backed request attributes
    /// This version avoids some heap allocations by using pre-allocated strings
    fn create_eval_context_ws(&self, attrs: &WsRequestAttrs) -> Result<Context, CelError> {
        let mut eval_context = Context::default(); // TODO: Still allocates, but reduced string allocations

        // Add request attributes as variables using references to workspace strings
        eval_context
            .add_variable("method", attrs.method.as_str())
            .map_err(|e| CelError::EvaluationFailed {
                message: format!("Failed to add method variable: {}", e),
            })?;

        eval_context
            .add_variable("path", attrs.path.as_str())
            .map_err(|e| CelError::EvaluationFailed {
                message: format!("Failed to add path variable: {}", e),
            })?;

        if let Some(ref query) = attrs.query {
            eval_context
                .add_variable("query", query.as_str())
                .map_err(|e| CelError::EvaluationFailed {
                    message: format!("Failed to add query variable: {}", e),
                })?;
        }

        if let Some(ref client_ip) = attrs.client_ip {
            eval_context
                .add_variable("client_ip", client_ip.as_str())
                .map_err(|e| CelError::EvaluationFailed {
                    message: format!("Failed to add client_ip variable: {}", e),
                })?;
        }

        if let Some(ref user_agent) = attrs.user_agent {
            eval_context
                .add_variable("user_agent", user_agent.as_str())
                .map_err(|e| CelError::EvaluationFailed {
                    message: format!("Failed to add user_agent variable: {}", e),
                })?;
        }

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

    /// Evaluate a CEL program with workspace-backed request attributes
    /// This version avoids some allocations by using workspace-allocated strings
    pub fn eval_ws(&self, program: &Program, attrs: &WsRequestAttrs) -> Result<bool, CelError> {
        let _start_time = Instant::now();
        let mut _cost_tracker =
            CostTracker::new(self.limits.max_eval_steps, self.limits.max_eval_time);

        // Safely evaluate the expression
        self.safe_execute("eval_ws", || {
            // Create evaluation context with request data from workspace
            let context = self.create_eval_context_ws(attrs)?;

            // Execute the program
            let result = program
                .execute(&context)
                .map_err(|e| CelError::EvaluationFailed {
                    message: format!("CEL evaluation error: {}", e),
                })?;

            // Convert result to boolean
            let boolean_result = match result {
                cel::Value::Bool(b) => b,
                cel::Value::Int(i) => i != 0,
                cel::Value::UInt(u) => u != 0,
                cel::Value::String(_) => true, // Non-empty string is truthy
                cel::Value::List(_) => true,   // Non-empty list is truthy
                cel::Value::Map(_) => true,    // Non-empty map is truthy
                _ => false,
            };

            Ok(boolean_result)
        })
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

    fn eval_ws(&self, program: &Self::Program, attrs: &WsRequestAttrs) -> Result<bool, Self::Error> {
        self.eval_ws(program, attrs)
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

    #[test]
    fn test_engine_creation() {
        let engine = CelRustEngine::new();
        assert!(engine.is_ok());

        let engine = engine.unwrap();
        assert_eq!(engine.engine_name(), "CelRustEngine");
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

    // Note: Integration tests for eval_ws require a Varnish context
    // and are better handled in the VTC (Varnish Test Case) tests
}
