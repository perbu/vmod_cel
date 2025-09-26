use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use varnish::vcl::Ctx;

mod bundle;
mod cel_engine;
mod cel_functions;
mod loader;
mod panic_safety;
mod policy_engine;
mod request_attrs;
mod safety_limits;
mod workspace;

#[cfg(test)]
mod workspace_tests;

pub use bundle::{BundleMetadata, CompiledRule, Rule, RuleBundle, RuleSet};
pub use cel_engine::CelRustEngine;
pub use loader::{BundleFormat, BundleLoader, LoadError, RuleSetSwapper};
pub use panic_safety::{
    CircuitBreaker, CircuitState, ErrorRecovery, PanicSafeWrapper, RecoveryStrategy,
};
pub use policy_engine::{CompiledProgram, EvalResult, PolicyEngine};
pub use request_attrs::{AttributeBuilder, AttributeConfig, WsRequestAttrs};
pub use safety_limits::{CostTracker, SafetyLimits};
pub use workspace::{WorkspaceConfig, WsHashMap, WsString};

pub struct CelConfig {
    pub enable_explain: bool,
    pub safety_limits: SafetyLimits,
    pub attribute_config: AttributeConfig,
}

impl CelConfig {
    pub fn new() -> Self {
        Self {
            enable_explain: false,
            safety_limits: SafetyLimits::default(),
            attribute_config: AttributeConfig::default(),
        }
    }

    /// Create production-ready configuration
    pub fn production() -> Self {
        Self {
            enable_explain: false,
            safety_limits: SafetyLimits::production(),
            attribute_config: AttributeConfig::default(),
        }
    }

    /// Create development-friendly configuration
    pub fn development() -> Self {
        Self {
            enable_explain: true,
            safety_limits: SafetyLimits::development(),
            attribute_config: AttributeConfig::default(),
        }
    }
}

impl Default for CelConfig {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CelMetrics {
    pub compiles_ok: AtomicU64,
    pub compiles_err: AtomicU64,
    pub eval_true: AtomicU64,
    pub eval_false: AtomicU64,
    pub eval_err: AtomicU64,
    pub reload_ok: AtomicU64,
    pub reload_err: AtomicU64,
}

impl CelMetrics {
    pub fn new() -> Self {
        Self {
            compiles_ok: AtomicU64::new(0),
            compiles_err: AtomicU64::new(0),
            eval_true: AtomicU64::new(0),
            eval_false: AtomicU64::new(0),
            eval_err: AtomicU64::new(0),
            reload_ok: AtomicU64::new(0),
            reload_err: AtomicU64::new(0),
        }
    }
}

impl Default for CelMetrics {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CelState {
    pub rules: Arc<RuleSet>,
    pub config: CelConfig,
    pub metrics: CelMetrics,
    pub engine: Arc<CelRustEngine>,
    pub rule_swapper: RuleSetSwapper,
    pub panic_wrapper: PanicSafeWrapper,
    pub circuit_breaker: CircuitBreaker,
    pub error_recovery: ErrorRecovery,
}

impl CelState {
    pub fn new() -> Result<Self, String> {
        let config = CelConfig::new();
        let engine = CelRustEngine::with_limits(config.safety_limits.clone())
            .map_err(|e| format!("Failed to create CEL engine: {}", e))?;

        Ok(Self {
            rules: Arc::new(RuleSet::new()),
            config,
            metrics: CelMetrics::new(),
            engine: Arc::new(engine),
            rule_swapper: RuleSetSwapper::new(),
            panic_wrapper: PanicSafeWrapper::new(),
            circuit_breaker: CircuitBreaker::new(5, 30000), // 5 failures, 30s recovery
            error_recovery: ErrorRecovery::new(RecoveryStrategy::ReturnDefault),
        })
    }

    pub fn new_with_attribute_config(attr_config: AttributeConfig) -> Result<Self, String> {
        let mut config = CelConfig::new();
        config.attribute_config = attr_config;

        let engine = CelRustEngine::with_limits(config.safety_limits.clone())
            .map_err(|e| format!("Failed to create CEL engine: {}", e))?;

        Ok(Self {
            rules: Arc::new(RuleSet::new()),
            config,
            metrics: CelMetrics::new(),
            engine: Arc::new(engine),
            rule_swapper: RuleSetSwapper::new(),
            panic_wrapper: PanicSafeWrapper::new(),
            circuit_breaker: CircuitBreaker::new(5, 30000), // 5 failures, 30s recovery
            error_recovery: ErrorRecovery::new(RecoveryStrategy::ReturnDefault),
        })
    }

    /// Compile and add a new rule (legacy method for compatibility)
    pub fn add_rule(&mut self, name: &str, expression: &str) -> Result<(), String> {
        // TODO: Phase 3 - Integrate with actual CEL compilation
        // For now, create a placeholder compiled rule
        let rule = Rule {
            name: name.to_string(),
            expr: expression.to_string(),
            enabled: true,
            description: None,
            tags: vec![],
        };

        // Compile the expression using the CEL engine
        let start_time = std::time::Instant::now();
        let program = self
            .engine
            .compile(name, expression)
            .map_err(|e| e.to_string())?;
        let compile_time_us = start_time.elapsed().as_micros() as u64;
        let estimated_cost = self
            .engine
            .estimate_cost(expression)
            .map_err(|e| e.to_string())?;

        let compiled_rule = CompiledRule {
            rule,
            program,
            estimated_cost,
            compile_time_us,
        };

        // Create new rule set with the single rule
        let mut rules = RuleSet::new();
        rules.programs.insert(name.to_string(), compiled_rule);

        // Atomic swap
        self.rules = Arc::new(rules);
        self.metrics.compiles_ok.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Evaluate a rule by name with full safety protection using workspace allocation
    pub fn eval_rule_ws(&self, rule_name: &str, ctx: &mut varnish::vcl::Ctx) -> Result<bool, String> {
        // Check circuit breaker first
        if let Err(e) = self.circuit_breaker.allow_request() {
            self.metrics.eval_err.fetch_add(1, Ordering::Relaxed);
            return self.error_recovery.recover_from_error(&e);
        }

        // Extract request attributes first (outside panic-safe closure)
        let attr_builder = AttributeBuilder::new(self.config.attribute_config.clone());
        let attrs = match attr_builder.extract_ws(ctx) {
            Ok(attrs) => attrs,
            Err(e) => {
                self.metrics.eval_err.fetch_add(1, Ordering::Relaxed);
                return Err(format!("Failed to extract request attributes: {}", e));
            }
        };

        // Execute with panic protection
        let evaluation_result = self.panic_wrapper.execute_safe(|| {
            // Get the compiled rule
            let compiled_rule = self
                .rules
                .get_rule(rule_name)
                .ok_or_else(|| format!("Rule '{}' not found", rule_name))?;

            // Evaluate using workspace-based method
            self.engine
                .eval_ws(&compiled_rule.program, &attrs)
                .map_err(|e| format!("CEL evaluation failed: {}", e))
        });

        match evaluation_result {
            Ok(result) => {
                // Success case
                self.circuit_breaker.record_success();
                if result {
                    self.metrics.eval_true.fetch_add(1, Ordering::Relaxed);
                } else {
                    self.metrics.eval_false.fetch_add(1, Ordering::Relaxed);
                }
                Ok(result)
            }
            Err(e) => {
                // Panic occurred and was caught, or evaluation error
                self.circuit_breaker.record_failure();
                self.metrics.eval_err.fetch_add(1, Ordering::Relaxed);
                eprintln!("CEL: Rule evaluation failed for '{}': {}", rule_name, e);
                self.error_recovery.recover_from_error(&e)
            }
        }
    }




    /// Evaluate all enabled rules, returning true if ANY match (logical OR) using workspace
    pub fn eval_any_rule_ws(&self, ctx: &mut varnish::vcl::Ctx) -> Result<bool, String> {
        // Check circuit breaker first
        if let Err(e) = self.circuit_breaker.allow_request() {
            self.metrics.eval_err.fetch_add(1, Ordering::Relaxed);
            return self.error_recovery.recover_from_error(&e);
        }

        // Extract request attributes first (outside panic-safe closure)
        let attr_builder = AttributeBuilder::new(self.config.attribute_config.clone());
        let attrs = match attr_builder.extract_ws(ctx) {
            Ok(attrs) => attrs,
            Err(e) => {
                self.metrics.eval_err.fetch_add(1, Ordering::Relaxed);
                return Err(format!("Failed to extract request attributes: {}", e));
            }
        };

        // Execute with panic protection
        let evaluation_result = self.panic_wrapper.execute_safe(|| {
            // Use iterator instead of collecting into Vec to avoid allocation
            let enabled_rules = self
                .rules
                .programs
                .iter()
                .filter(|(_, rule)| rule.rule.enabled);

            // Evaluate each enabled rule until one matches
            for (rule_name, compiled_rule) in enabled_rules {
                match self.engine.eval_ws(&compiled_rule.program, &attrs) {
                    Ok(result) => {
                        if result {
                            self.metrics.eval_true.fetch_add(1, Ordering::Relaxed);
                        } else {
                            self.metrics.eval_false.fetch_add(1, Ordering::Relaxed);
                        }

                        // Short-circuit on first match
                        if result {
                            return Ok(true);
                        }
                    }
                    Err(e) => {
                        self.metrics.eval_err.fetch_add(1, Ordering::Relaxed);
                        eprintln!("CEL: Error evaluating rule '{}': {}", rule_name, e);
                        // Continue evaluating other rules on error
                    }
                }
            }

            // No rules matched
            Ok(false)
        });

        // Handle the result
        match evaluation_result {
            Ok(result) => {
                self.circuit_breaker.record_success();
                Ok(result)
            }
            Err(e) => {
                self.circuit_breaker.record_failure();
                self.error_recovery.recover_from_error(&e)
            }
        }
    }

    /// Evaluate all enabled rules, returning true if ALL match (logical AND) using workspace
    pub fn eval_all_rule_ws(&self, ctx: &mut varnish::vcl::Ctx) -> Result<bool, String> {
        // Check circuit breaker first
        if let Err(e) = self.circuit_breaker.allow_request() {
            self.metrics.eval_err.fetch_add(1, Ordering::Relaxed);
            return self.error_recovery.recover_from_error(&e);
        }

        // Extract request attributes first (outside panic-safe closure)
        let attr_builder = AttributeBuilder::new(self.config.attribute_config.clone());
        let attrs = match attr_builder.extract_ws(ctx) {
            Ok(attrs) => attrs,
            Err(e) => {
                self.metrics.eval_err.fetch_add(1, Ordering::Relaxed);
                return Err(format!("Failed to extract request attributes: {}", e));
            }
        };

        // Execute with panic protection
        let evaluation_result = self.panic_wrapper.execute_safe(|| {
            // Use iterator instead of collecting into Vec to avoid allocation
            let enabled_rules = self
                .rules
                .programs
                .iter()
                .filter(|(_, rule)| rule.rule.enabled);

            // If no enabled rules, return true (vacuous truth - all zero rules match)
            for (rule_name, compiled_rule) in enabled_rules {
                match self.engine.eval_ws(&compiled_rule.program, &attrs) {
                    Ok(result) => {
                        if result {
                            self.metrics.eval_true.fetch_add(1, Ordering::Relaxed);
                        } else {
                            self.metrics.eval_false.fetch_add(1, Ordering::Relaxed);
                        }

                        // Short-circuit on first non-match
                        if !result {
                            return Ok(false);
                        }
                    }
                    Err(e) => {
                        self.metrics.eval_err.fetch_add(1, Ordering::Relaxed);
                        eprintln!("CEL: Error evaluating rule '{}': {}", rule_name, e);
                        // Evaluation error counts as non-match
                        return Ok(false);
                    }
                }
            }

            // All rules matched (or no rules found - vacuous truth)
            Ok(true)
        });

        // Handle the result
        match evaluation_result {
            Ok(result) => {
                self.circuit_breaker.record_success();
                Ok(result)
            }
            Err(e) => {
                self.circuit_breaker.record_failure();
                self.error_recovery.recover_from_error(&e)
            }
        }
    }



    /// Set explain mode
    pub fn set_explain_mode(&mut self, enabled: bool) {
        self.config.enable_explain = enabled;
    }

    /// Get safety and stability status
    pub fn get_safety_status(&self) -> SafetyStatus {
        let panic_stats = self.panic_wrapper.get_panic_stats();
        let error_stats = self.error_recovery.get_error_stats();
        let circuit_state = self.circuit_breaker.get_state();
        let failure_count = self.circuit_breaker.get_failure_count();

        SafetyStatus {
            panic_count: panic_stats.panic_count,
            recovery_count: panic_stats.recovery_count,
            error_count: error_stats.error_count,
            error_recovery_count: error_stats.recovery_success_count,
            circuit_breaker_state: format!("{:?}", circuit_state),
            circuit_failure_count: failure_count,
            total_evaluations: self.metrics.eval_true.load(Ordering::Relaxed)
                + self.metrics.eval_false.load(Ordering::Relaxed)
                + self.metrics.eval_err.load(Ordering::Relaxed),
        }
    }
}

/// Safety and stability status report
#[derive(Debug, Clone)]
pub struct SafetyStatus {
    pub panic_count: u64,
    pub recovery_count: u64,
    pub error_count: u64,
    pub error_recovery_count: u64,
    pub circuit_breaker_state: String,
    pub circuit_failure_count: u64,
    pub total_evaluations: u64,
}

impl SafetyStatus {
    pub fn is_healthy(&self) -> bool {
        // System is healthy if:
        // - No recent panics (or very few relative to total evaluations)
        // - Circuit breaker is closed
        // - Error recovery is working effectively

        let panic_rate = if self.total_evaluations > 0 {
            self.panic_count as f64 / self.total_evaluations as f64
        } else {
            0.0
        };

        let error_recovery_rate = if self.error_count > 0 {
            self.error_recovery_count as f64 / self.error_count as f64
        } else {
            1.0 // No errors is good
        };

        panic_rate < 0.01 && // Less than 1% panic rate
        self.circuit_breaker_state == "Closed" &&
        error_recovery_rate > 0.8 // 80% error recovery success
    }

    pub fn format_status(&self) -> String {
        let health = if self.is_healthy() {
            "✅ HEALTHY"
        } else {
            "⚠️ DEGRADED"
        };

        format!(
            "{}\nEvaluations: {} | Panics: {} | Errors: {} (Recovered: {}) | Circuit: {} (Failures: {})",
            health,
            self.total_evaluations,
            self.panic_count,
            self.error_count,
            self.error_recovery_count,
            self.circuit_breaker_state,
            self.circuit_failure_count
        )
    }
}

static CEL_STATE: Mutex<Option<CelState>> = Mutex::new(None);

#[varnish::vmod(docs = "README.md")]
mod cel {
    use super::*;

    /// Initialize the VMOD (called manually from VCL)
    pub fn init() -> Result<(), String> {
        let mut guard = CEL_STATE.lock().unwrap();
        if guard.is_none() {
            *guard = Some(CelState::new()?);
        }
        Ok(())
    }

    /// Load CEL rules from a file
    pub fn load_file(path: &str) -> Result<(), String> {
        let mut guard = CEL_STATE.lock().unwrap();
        let cel_state = match guard.as_mut() {
            Some(state) => state,
            None => return Err("VMOD not initialized".to_string()),
        };

        // Load and swap rule set using the swapper
        match cel_state.rule_swapper.load_and_swap(path) {
            Ok(_old_rules) => {
                // Update the current rules reference for compatibility
                cel_state.rules = cel_state.rule_swapper.get();
                cel_state.metrics.reload_ok.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                cel_state.metrics.reload_err.fetch_add(1, Ordering::Relaxed);
                Err(format!("Failed to load rules from '{}': {}", path, e))
            }
        }
    }

    /// Configure attribute extraction settings
    pub fn configure_attributes(
        extract_cookies: bool,
        max_headers: i64,
        max_header_size: i64,
    ) -> Result<(), String> {
        if !(1..=1000).contains(&max_headers) {
            return Err("max_headers must be between 1 and 1000".to_string());
        }

        if !(1024..=1048576).contains(&max_header_size) {
            return Err("max_header_size must be between 1KB and 1MB".to_string());
        }

        let mut guard = CEL_STATE.lock().unwrap();
        if let Some(cel_state) = guard.as_mut() {
            cel_state.config.attribute_config = AttributeConfig {
                extract_cookies,
                max_headers: max_headers as usize,
                max_header_value_size: max_header_size as usize,
                ..AttributeConfig::default()
            };
            Ok(())
        } else {
            Err("VMOD not initialized".to_string())
        }
    }

    /// Get metrics summary
    pub fn metrics_summary() -> String {
        let guard = CEL_STATE.lock().unwrap();
        match guard.as_ref() {
            Some(cel_state) => {
                format!(
                    "Compiles OK: {}, Errors: {} | Evals True: {}, False: {}, Errors: {} | Reloads OK: {}, Errors: {}",
                    cel_state.metrics.compiles_ok.load(Ordering::Relaxed),
                    cel_state.metrics.compiles_err.load(Ordering::Relaxed),
                    cel_state.metrics.eval_true.load(Ordering::Relaxed),
                    cel_state.metrics.eval_false.load(Ordering::Relaxed),
                    cel_state.metrics.eval_err.load(Ordering::Relaxed),
                    cel_state.metrics.reload_ok.load(Ordering::Relaxed),
                    cel_state.metrics.reload_err.load(Ordering::Relaxed),
                )
            }
            None => "VMOD not initialized".to_string(),
        }
    }

    /// Evaluate all enabled rules, returning true if ANY match (logical OR)
    pub fn eval_any(ctx: &mut Ctx) -> bool {
        let guard = match CEL_STATE.lock() {
            Ok(guard) => guard,
            Err(e) => {
                eprintln!("CEL: Failed to acquire state lock in eval_any(): {}", e);
                return false;
            }
        };

        let cel_state = match guard.as_ref() {
            Some(state) => state,
            None => {
                eprintln!("CEL: VMOD not initialized in eval_any()");
                return false;
            }
        };

        // Check if any enabled rules exist
        let enabled_count = cel_state.rules.enabled_rule_count();
        if enabled_count == 0 {
            return false; // No enabled rules, nothing can match
        }

        // Use workspace-based evaluation for better performance
        cel_state.eval_any_rule_ws(ctx).unwrap_or(false)
    }

    /// Evaluate all enabled rules, returning true if ALL match (logical AND)
    pub fn eval_all(ctx: &mut Ctx) -> bool {
        let guard = match CEL_STATE.lock() {
            Ok(guard) => guard,
            Err(e) => {
                eprintln!("CEL: Failed to acquire state lock in eval_all(): {}", e);
                return false;
            }
        };

        let cel_state = match guard.as_ref() {
            Some(state) => state,
            None => {
                eprintln!("CEL: VMOD not initialized in eval_all()");
                return false;
            }
        };

        // Check if any enabled rules exist
        let enabled_count = cel_state.rules.enabled_rule_count();
        if enabled_count == 0 {
            return true; // No enabled rules, vacuous truth (all zero rules match)
        }

        // Use workspace-based evaluation for better performance
        cel_state.eval_all_rule_ws(ctx).unwrap_or(true)
    }

    /// Get safety and stability status (Phase 6)
    pub fn safety_status() -> String {
        let guard = match CEL_STATE.lock() {
            Ok(guard) => guard,
            Err(e) => {
                return format!("Failed to acquire state lock: {}", e);
            }
        };

        match guard.as_ref() {
            Some(cel_state) => {
                let status = cel_state.get_safety_status();
                status.format_status()
            }
            None => "VMOD not initialized".to_string(),
        }
    }
}

// VTC tests will be added back in Phase 2c
// varnish::run_vtc_tests!("tests/*.vtc");
