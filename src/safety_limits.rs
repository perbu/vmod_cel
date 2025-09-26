use std::time::{Duration, Instant};
use thiserror::Error;

/// Safety limits for CEL expression compilation and evaluation
#[derive(Debug, Clone)]
pub struct SafetyLimits {
    /// Maximum size of a rule expression in bytes
    pub max_expression_size: usize,

    /// Maximum number of AST nodes in a compiled expression
    pub max_ast_nodes: usize,

    /// Maximum AST depth (to prevent stack overflow)
    pub max_ast_depth: usize,

    /// Maximum size of regex patterns in characters
    pub max_regex_size: usize,

    /// Maximum size of string literals in characters
    pub max_string_literal_size: usize,

    /// Maximum evaluation steps (cost units)
    pub max_eval_steps: u64,

    /// Hard timeout for evaluation (emergency brake)
    pub max_eval_time: Duration,

    /// Maximum memory per evaluation context
    pub max_eval_memory_bytes: usize,
}

impl Default for SafetyLimits {
    fn default() -> Self {
        Self {
            max_expression_size: 16 * 1024,            // 16KB
            max_ast_nodes: 1000,                       // Reasonable AST complexity
            max_ast_depth: 32,                         // Prevent deep recursion
            max_regex_size: 500,                       // Conservative regex size
            max_string_literal_size: 1024,             // 1KB string literals
            max_eval_steps: 10_000,                    // Cost units budget
            max_eval_time: Duration::from_millis(100), // 100ms hard timeout
            max_eval_memory_bytes: 10 * 1024 * 1024,   // 10MB per evaluation
        }
    }
}

impl SafetyLimits {
    /// Create production-ready safety limits (more restrictive)
    pub fn production() -> Self {
        Self {
            max_expression_size: 8 * 1024,            // 8KB
            max_ast_nodes: 500,                       // Stricter AST complexity
            max_ast_depth: 24,                        // Stricter depth limit
            max_regex_size: 256,                      // Smaller regex limit
            max_string_literal_size: 512,             // Smaller string literals
            max_eval_steps: 5_000,                    // Tighter cost budget
            max_eval_time: Duration::from_millis(50), // 50ms timeout
            max_eval_memory_bytes: 5 * 1024 * 1024,   // 5MB per evaluation
        }
    }

    /// Create development-friendly limits (more permissive)
    pub fn development() -> Self {
        Self {
            max_expression_size: 32 * 1024,            // 32KB
            max_ast_nodes: 2000,                       // More permissive
            max_ast_depth: 48,                         // Deeper nesting allowed
            max_regex_size: 1024,                      // Larger regex patterns
            max_string_literal_size: 2048,             // Larger string literals
            max_eval_steps: 25_000,                    // Higher cost budget
            max_eval_time: Duration::from_millis(200), // 200ms timeout
            max_eval_memory_bytes: 20 * 1024 * 1024,   // 20MB per evaluation
        }
    }

    /// Validate expression size
    pub fn check_expression_size(&self, expr: &str) -> Result<(), SafetyError> {
        if expr.len() > self.max_expression_size {
            return Err(SafetyError::ExpressionTooLarge {
                size: expr.len(),
                limit: self.max_expression_size,
            });
        }
        Ok(())
    }

    /// Validate regex pattern size
    pub fn check_regex_size(&self, pattern: &str) -> Result<(), SafetyError> {
        if pattern.len() > self.max_regex_size {
            return Err(SafetyError::RegexTooLarge {
                size: pattern.len(),
                limit: self.max_regex_size,
            });
        }
        Ok(())
    }

    /// Validate string literal size
    pub fn check_string_literal_size(&self, literal: &str) -> Result<(), SafetyError> {
        if literal.len() > self.max_string_literal_size {
            return Err(SafetyError::StringLiteralTooLarge {
                size: literal.len(),
                limit: self.max_string_literal_size,
            });
        }
        Ok(())
    }
}

/// Cost tracker for evaluation step counting
#[derive(Debug, Clone)]
pub struct CostTracker {
    steps_used: u64,
    max_steps: u64,
    start_time: Instant,
    max_time: Duration,
}

impl CostTracker {
    pub fn new(max_steps: u64, max_time: Duration) -> Self {
        Self {
            steps_used: 0,
            max_steps,
            start_time: Instant::now(),
            max_time,
        }
    }

    /// Add cost units and check limits
    pub fn add_cost(&mut self, cost: u64) -> Result<(), SafetyError> {
        self.steps_used += cost;

        // Check step budget
        if self.steps_used > self.max_steps {
            return Err(SafetyError::StepBudgetExceeded {
                used: self.steps_used,
                limit: self.max_steps,
            });
        }

        // Check time budget
        let elapsed = self.start_time.elapsed();
        if elapsed > self.max_time {
            return Err(SafetyError::TimeBudgetExceeded {
                elapsed_ms: elapsed.as_millis() as u64,
                limit_ms: self.max_time.as_millis() as u64,
            });
        }

        Ok(())
    }

    /// Get current step count
    pub fn steps_used(&self) -> u64 {
        self.steps_used
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Get elapsed time in microseconds
    pub fn elapsed_us(&self) -> u64 {
        self.start_time.elapsed().as_micros() as u64
    }
}

/// Safety-related errors
#[derive(Error, Debug)]
pub enum SafetyError {
    #[error("Expression too large: {size} bytes exceeds limit of {limit} bytes")]
    ExpressionTooLarge { size: usize, limit: usize },

    #[error("AST too complex: {nodes} nodes exceeds limit of {limit} nodes")]
    AstTooComplex { nodes: usize, limit: usize },

    #[error("AST too deep: {depth} levels exceeds limit of {limit} levels")]
    AstTooDeep { depth: usize, limit: usize },

    #[error("Regex pattern too large: {size} characters exceeds limit of {limit} characters")]
    RegexTooLarge { size: usize, limit: usize },

    #[error("String literal too large: {size} characters exceeds limit of {limit} characters")]
    StringLiteralTooLarge { size: usize, limit: usize },

    #[error("Evaluation step budget exceeded: {used} steps exceeds limit of {limit} steps")]
    StepBudgetExceeded { used: u64, limit: u64 },

    #[error("Evaluation time budget exceeded: {elapsed_ms}ms exceeds limit of {limit_ms}ms")]
    TimeBudgetExceeded { elapsed_ms: u64, limit_ms: u64 },

    #[error("Memory budget exceeded: {used} bytes exceeds limit of {limit} bytes")]
    MemoryBudgetExceeded { used: usize, limit: usize },

    #[error("Operation timed out")]
    Timeout,

    #[error("Resource exhausted: {resource}")]
    ResourceExhausted { resource: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_limits_defaults() {
        let limits = SafetyLimits::default();
        assert_eq!(limits.max_expression_size, 16 * 1024);
        assert_eq!(limits.max_ast_nodes, 1000);
        assert_eq!(limits.max_ast_depth, 32);
        assert_eq!(limits.max_regex_size, 500);
        assert_eq!(limits.max_string_literal_size, 1024);
        assert_eq!(limits.max_eval_steps, 10_000);
        assert_eq!(limits.max_eval_time, Duration::from_millis(100));
        assert_eq!(limits.max_eval_memory_bytes, 10 * 1024 * 1024);
    }

    #[test]
    fn test_production_limits_more_restrictive() {
        let default_limits = SafetyLimits::default();
        let prod_limits = SafetyLimits::production();

        assert!(prod_limits.max_expression_size < default_limits.max_expression_size);
        assert!(prod_limits.max_ast_nodes < default_limits.max_ast_nodes);
        assert!(prod_limits.max_eval_steps < default_limits.max_eval_steps);
        assert!(prod_limits.max_eval_time < default_limits.max_eval_time);
    }

    #[test]
    fn test_expression_size_check() {
        let limits = SafetyLimits::default();

        // Should pass
        assert!(limits.check_expression_size("small expression").is_ok());

        // Should fail
        let large_expr = "x".repeat(limits.max_expression_size + 1);
        assert!(limits.check_expression_size(&large_expr).is_err());
    }

    #[test]
    fn test_cost_tracker() {
        let mut tracker = CostTracker::new(100, Duration::from_millis(1000));

        // Should pass
        assert!(tracker.add_cost(50).is_ok());
        assert_eq!(tracker.steps_used(), 50);

        // Should fail - exceeds step budget
        assert!(tracker.add_cost(60).is_err());
    }

    #[test]
    fn test_cost_tracker_time_budget() {
        let mut tracker = CostTracker::new(10000, Duration::from_nanos(1));

        // Sleep to exceed time budget
        std::thread::sleep(Duration::from_millis(1));

        // Should fail - exceeds time budget
        assert!(tracker.add_cost(1).is_err());
    }
}
