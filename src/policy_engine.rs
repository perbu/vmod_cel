use crate::request_attrs::WsRequestAttrs;
use std::fmt::Debug;

/// PolicyEngine trait defines the interface for rule evaluation engines
///
/// This trait provides a generic interface for compiling and evaluating rules
/// against HTTP request attributes. Different implementations can be used for
/// different rule languages (CEL, JavaScript, etc.).
pub trait PolicyEngine: Send + Sync + 'static {
    /// Compiled program/rule representation
    type Program: Send + Sync + Debug;

    /// Engine-specific error type
    type Error: std::error::Error + Send + Sync + 'static;

    /// Compile a rule expression into an executable program
    ///
    /// # Arguments
    /// * `name` - Name/identifier for the rule (used for logging/debugging)
    /// * `expr` - Rule expression string
    ///
    /// # Returns
    /// * `Ok(Program)` - Successfully compiled program
    /// * `Err(Error)` - Compilation error with details
    fn compile(&self, name: &str, expr: &str) -> Result<Self::Program, Self::Error>;

    /// Evaluate a compiled program against workspace request attributes
    ///
    /// # Arguments
    /// * `program` - Compiled program from compile()
    /// * `attrs` - Workspace-backed request attributes to evaluate against
    ///
    /// # Returns
    /// * `Ok(true)` - Rule matched/condition is true
    /// * `Ok(false)` - Rule did not match/condition is false
    /// * `Err(Error)` - Evaluation error (treated as false in production)
    fn eval_ws(&self, program: &Self::Program, attrs: &WsRequestAttrs) -> Result<bool, Self::Error>;

    /// Validate a rule expression without compiling it
    ///
    /// This is useful for checking syntax and basic validity without
    /// the overhead of full compilation.
    ///
    /// # Arguments
    /// * `expr` - Rule expression string to validate
    ///
    /// # Returns
    /// * `Ok(())` - Expression is valid
    /// * `Err(Error)` - Validation error with details
    fn validate_expr(&self, expr: &str) -> Result<(), Self::Error>;

    /// Estimate the computational cost of an expression
    ///
    /// Returns an estimated cost in "cost units" for the expression.
    /// This helps enforce safety limits and provides feedback to users
    /// about expression complexity.
    ///
    /// # Arguments
    /// * `expr` - Rule expression string
    ///
    /// # Returns
    /// * `Ok(cost)` - Estimated cost in cost units
    /// * `Err(Error)` - Error estimating cost
    fn estimate_cost(&self, expr: &str) -> Result<u64, Self::Error>;

    /// Get engine name for logging and debugging
    fn engine_name(&self) -> &'static str;

    /// Get engine version string
    fn engine_version(&self) -> String;
}

/// Program wrapper that includes metadata and the actual compiled program
#[derive(Debug, Clone)]
pub struct CompiledProgram<P> {
    pub name: String,
    pub expression: String,
    pub program: P,
    pub estimated_cost: u64,
    pub compile_time_us: u64,
}

impl<P> CompiledProgram<P> {
    pub fn new(
        name: String,
        expression: String,
        program: P,
        estimated_cost: u64,
        compile_time_us: u64,
    ) -> Self {
        Self {
            name,
            expression,
            program,
            estimated_cost,
            compile_time_us,
        }
    }
}

/// Evaluation result with metadata
#[derive(Debug, Clone)]
pub struct EvalResult {
    pub result: bool,
    pub evaluation_time_us: u64,
    pub cost_used: u64,
}

impl EvalResult {
    pub fn new(result: bool, evaluation_time_us: u64, cost_used: u64) -> Self {
        Self {
            result,
            evaluation_time_us,
            cost_used,
        }
    }
}
