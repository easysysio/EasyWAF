// =========================================================
// modules/mod.rs — EasyWAF
// Inspection module pipeline.
//
// Each module receives a RequestContext and returns one of:
//   Pass  — allow, continue to next module
//   Alert — flag the request (logged) but continue
//   Drop  — block the request immediately, stop the chain
//
// The pipeline runs modules in order; the first Drop wins.
// =========================================================

pub mod traffic;

use axum::http::StatusCode;
use std::net::IpAddr;
use bytes::Bytes;
use axum::http::{HeaderMap, Method};

// ─── RequestContext ───────────────────────────────────────

/// All information about an incoming request, shared across modules.
/// Fields are read by GeoIP, WAF-rules, and other future modules.
#[allow(dead_code)]
pub struct RequestContext {
    pub site_id:    i64,
    pub site_name:  String,
    pub client_ip:  IpAddr,
    pub method:     Method,
    pub host:       String,
    pub path:       String,
    pub query:      Option<String>,
    pub headers:    HeaderMap,
    pub body:       Bytes,
    /// Wall-clock time the request arrived (for response_ms calculation).
    pub started_at: std::time::Instant,
}

// ─── ModuleDecision ──────────────────────────────────────

/// Decision returned by a single module.
/// Alert and Drop are not yet produced by any built-in module but will be
/// used by the GeoIP and WAF-rules modules when they are implemented.
#[derive(Debug)]
#[allow(dead_code)]
pub enum ModuleDecision {
    /// Request is clean — pass to the next module.
    Pass,
    /// Request is suspicious — log the alert and continue.
    Alert { reason: String },
    /// Request is malicious — block it, stop the chain.
    Drop { reason: String, status: StatusCode },
}

// ─── Alert ───────────────────────────────────────────────

/// A non-blocking alert raised by a module.
/// Will be written to traffic_events once the alerting pipeline is wired up.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Alert {
    pub module: &'static str,
    pub reason: String,
}

// ─── PipelineVerdict ─────────────────────────────────────

/// Final outcome after all modules have run.
/// The `alerts` field is populated now but only read once alert-logging is implemented.
#[derive(Debug)]
#[allow(dead_code)]
pub enum PipelineVerdict {
    /// Forward to upstream. May carry alerts from intermediate modules.
    Allow { alerts: Vec<Alert> },
    /// Block the request. The chain was stopped by one module.
    Block {
        reason:  String,
        status:  StatusCode,
        alerts:  Vec<Alert>,
    },
}

// ─── InspectionModule ────────────────────────────────────

/// Trait every module must implement.
#[async_trait::async_trait]
pub trait InspectionModule: Send + Sync {
    /// Short identifying name used in logs and traffic_events.
    fn name(&self) -> &'static str;

    /// Inspect the request and return a decision.
    async fn inspect(&self, ctx: &RequestContext) -> ModuleDecision;
}

// ─── Pipeline ────────────────────────────────────────────

/// Ordered list of modules. Run them in sequence; stop on the first Drop.
pub struct Pipeline {
    modules: Vec<Box<dyn InspectionModule>>,
}

impl Pipeline {
    // ── new ──────────────────────────────────────────────

    pub fn new() -> Self {
        Self { modules: Vec::new() }
    }

    // ── add ──────────────────────────────────────────────

    pub fn add<M: InspectionModule + 'static>(&mut self, module: M) {
        self.modules.push(Box::new(module));
    }

    // ── run ──────────────────────────────────────────────

    /// Execute all modules in order and return the final verdict.
    pub async fn run(&self, ctx: &RequestContext) -> PipelineVerdict {
        let mut alerts = Vec::new();

        for module in &self.modules {
            match module.inspect(ctx).await {
                ModuleDecision::Pass => {}

                ModuleDecision::Alert { reason } => {
                    tracing::debug!(
                        module = module.name(),
                        reason = %reason,
                        "module alert"
                    );
                    alerts.push(Alert { module: module.name(), reason });
                }

                ModuleDecision::Drop { reason, status } => {
                    tracing::info!(
                        module = module.name(),
                        reason = %reason,
                        status = status.as_u16(),
                        "request blocked"
                    );
                    return PipelineVerdict::Block { reason, status, alerts };
                }
            }
        }

        PipelineVerdict::Allow { alerts }
    }
}

impl Default for Pipeline {
    fn default() -> Self { Self::new() }
}
