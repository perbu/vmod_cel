use std::panic;
use std::sync::atomic::{AtomicU64, Ordering};

/// Panic safety wrapper for CEL operations
///
/// This module provides panic isolation to ensure that panics in CEL evaluation
/// don't crash the Varnish process. All panics are caught and converted to
/// evaluation errors.
pub struct PanicSafeWrapper {
    panic_count: AtomicU64,
    recovery_count: AtomicU64,
}

impl PanicSafeWrapper {
    pub fn new() -> Self {
        Self {
            panic_count: AtomicU64::new(0),
            recovery_count: AtomicU64::new(0),
        }
    }

    /// Execute a CEL operation with panic protection
    pub fn execute_safe<F, T>(&self, operation: F) -> Result<T, String>
    where
        F: FnOnce() -> Result<T, String> + panic::UnwindSafe,
    {
        match panic::catch_unwind(operation) {
            Ok(result) => {
                // Operation completed without panic
                result
            }
            Err(panic_payload) => {
                // Panic occurred - increment counter and return error
                self.panic_count.fetch_add(1, Ordering::Relaxed);
                self.recovery_count.fetch_add(1, Ordering::Relaxed);

                // Try to extract panic message
                let panic_msg = if let Some(msg) = panic_payload.downcast_ref::<String>() {
                    msg.clone()
                } else if let Some(msg) = panic_payload.downcast_ref::<&str>() {
                    (*msg).to_string()
                } else {
                    "Unknown panic occurred".to_string()
                };

                // Log the panic for debugging (in production, this would go to Varnish logs)
                eprintln!("CEL: Panic caught and recovered: {}", panic_msg);

                Err(format!(
                    "CEL operation failed due to internal error: {}",
                    panic_msg
                ))
            }
        }
    }

    /// Get panic statistics
    pub fn get_panic_stats(&self) -> PanicStats {
        PanicStats {
            panic_count: self.panic_count.load(Ordering::Relaxed),
            recovery_count: self.recovery_count.load(Ordering::Relaxed),
        }
    }

    /// Reset panic counters (for testing)
    pub fn reset_stats(&self) {
        self.panic_count.store(0, Ordering::Relaxed);
        self.recovery_count.store(0, Ordering::Relaxed);
    }
}

impl Default for PanicSafeWrapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Panic statistics for monitoring
#[derive(Debug, Clone)]
pub struct PanicStats {
    pub panic_count: u64,
    pub recovery_count: u64,
}

/// Error recovery strategies
pub enum RecoveryStrategy {
    /// Return a safe default value and continue
    ReturnDefault,
    /// Log error and return false (safe for boolean CEL results)
    ReturnFalse,
    /// Fail fast and propagate error
    FailFast,
}

pub struct ErrorRecovery {
    strategy: RecoveryStrategy,
    error_count: AtomicU64,
    recovery_success_count: AtomicU64,
}

impl ErrorRecovery {
    pub fn new(strategy: RecoveryStrategy) -> Self {
        Self {
            strategy,
            error_count: AtomicU64::new(0),
            recovery_success_count: AtomicU64::new(0),
        }
    }

    /// Attempt to recover from a CEL evaluation error
    pub fn recover_from_error(&self, error: &str) -> Result<bool, String> {
        self.error_count.fetch_add(1, Ordering::Relaxed);

        match self.strategy {
            RecoveryStrategy::ReturnDefault => {
                self.recovery_success_count.fetch_add(1, Ordering::Relaxed);
                eprintln!("CEL: Error recovered with default value: {}", error);
                Ok(false) // Safe default for boolean CEL results
            }
            RecoveryStrategy::ReturnFalse => {
                self.recovery_success_count.fetch_add(1, Ordering::Relaxed);
                eprintln!("CEL: Error recovered with false: {}", error);
                Ok(false)
            }
            RecoveryStrategy::FailFast => {
                eprintln!("CEL: Error not recovered, failing fast: {}", error);
                Err(error.to_string())
            }
        }
    }

    pub fn get_error_stats(&self) -> ErrorStats {
        ErrorStats {
            error_count: self.error_count.load(Ordering::Relaxed),
            recovery_success_count: self.recovery_success_count.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ErrorStats {
    pub error_count: u64,
    pub recovery_success_count: u64,
}

/// Circuit breaker to prevent cascading failures
pub struct CircuitBreaker {
    failure_threshold: u64,
    recovery_timeout_ms: u64,
    failure_count: AtomicU64,
    last_failure_time: std::sync::Mutex<Option<std::time::Instant>>,
    state: std::sync::Mutex<CircuitState>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,   // Normal operation
    Open,     // Failing, rejecting requests
    HalfOpen, // Testing if service recovered
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u64, recovery_timeout_ms: u64) -> Self {
        Self {
            failure_threshold,
            recovery_timeout_ms,
            failure_count: AtomicU64::new(0),
            last_failure_time: std::sync::Mutex::new(None),
            state: std::sync::Mutex::new(CircuitState::Closed),
        }
    }

    /// Check if operation should be allowed through the circuit breaker
    pub fn allow_request(&self) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();

        match *state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                // Check if recovery timeout has passed
                let last_failure = self.last_failure_time.lock().unwrap();
                if let Some(failure_time) = *last_failure {
                    let elapsed = failure_time.elapsed().as_millis() as u64;
                    if elapsed >= self.recovery_timeout_ms {
                        *state = CircuitState::HalfOpen;
                        Ok(())
                    } else {
                        Err("Circuit breaker is open - too many recent failures".to_string())
                    }
                } else {
                    Err("Circuit breaker is open".to_string())
                }
            }
            CircuitState::HalfOpen => Ok(()),
        }
    }

    /// Record a successful operation
    pub fn record_success(&self) {
        let mut state = self.state.lock().unwrap();
        match *state {
            CircuitState::HalfOpen => {
                // Recovery successful, close circuit
                *state = CircuitState::Closed;
                self.failure_count.store(0, Ordering::Relaxed);
            }
            _ => {
                // Normal successful operation
            }
        }
    }

    /// Record a failed operation
    pub fn record_failure(&self) {
        let failures = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;

        if failures >= self.failure_threshold {
            let mut state = self.state.lock().unwrap();
            *state = CircuitState::Open;

            let mut last_failure = self.last_failure_time.lock().unwrap();
            *last_failure = Some(std::time::Instant::now());
        }
    }

    pub fn get_state(&self) -> CircuitState {
        self.state.lock().unwrap().clone()
    }

    pub fn get_failure_count(&self) -> u64 {
        self.failure_count.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panic_safety_normal_operation() {
        let wrapper = PanicSafeWrapper::new();

        let result = wrapper.execute_safe(|| Ok(42));
        assert_eq!(result, Ok(42));

        let stats = wrapper.get_panic_stats();
        assert_eq!(stats.panic_count, 0);
        assert_eq!(stats.recovery_count, 0);
    }

    #[test]
    fn test_panic_safety_panic_recovery() {
        let wrapper = PanicSafeWrapper::new();

        let result: Result<(), String> = wrapper.execute_safe(|| {
            panic!("Test panic");
            #[allow(unreachable_code)]
            Ok(())
        });

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Test panic"));

        let stats = wrapper.get_panic_stats();
        assert_eq!(stats.panic_count, 1);
        assert_eq!(stats.recovery_count, 1);
    }

    #[test]
    fn test_error_recovery_return_default() {
        let recovery = ErrorRecovery::new(RecoveryStrategy::ReturnDefault);

        let result = recovery.recover_from_error("Test error");
        assert_eq!(result, Ok(false));

        let stats = recovery.get_error_stats();
        assert_eq!(stats.error_count, 1);
        assert_eq!(stats.recovery_success_count, 1);
    }

    #[test]
    fn test_error_recovery_fail_fast() {
        let recovery = ErrorRecovery::new(RecoveryStrategy::FailFast);

        let result = recovery.recover_from_error("Test error");
        assert!(result.is_err());

        let stats = recovery.get_error_stats();
        assert_eq!(stats.error_count, 1);
        assert_eq!(stats.recovery_success_count, 0);
    }

    #[test]
    fn test_circuit_breaker_normal_operation() {
        let breaker = CircuitBreaker::new(3, 1000);

        assert!(breaker.allow_request().is_ok());
        breaker.record_success();
        assert_eq!(breaker.get_state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_failure_threshold() {
        let breaker = CircuitBreaker::new(2, 1000);

        // First failure
        breaker.record_failure();
        assert!(breaker.allow_request().is_ok());
        assert_eq!(breaker.get_state(), CircuitState::Closed);

        // Second failure - should open circuit
        breaker.record_failure();
        assert_eq!(breaker.get_state(), CircuitState::Open);
        assert!(breaker.allow_request().is_err());
    }
}
