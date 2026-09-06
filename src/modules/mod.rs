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

pub mod geoip;
pub mod traffic;
pub mod waf;

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
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
    Alert { reason: String, findings: Findings },
    /// Request is suspicious-but-maybe-legit — show a CAPTCHA challenge.
    Challenge { reason: String, findings: Findings },
    /// Request is malicious — block it, stop the chain.
    Drop { reason: String, status: StatusCode, findings: Findings },
}

// ─── RuleHit ─────────────────────────────────────────────

/// One rule that matched, as the Traffic Monitor will show it.
///
/// Carried out of the module rather than only logged. The WAF knows exactly
/// why it decided what it did; until now that knowledge reached a debug log
/// and nowhere else, so diagnosing a false positive meant enabling debug
/// logging on a production proxy and reproducing the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHit {
    /// The OWASP-style catalogue number, when the rule has one.
    pub id:    Option<i64>,
    pub name:  String,
    pub score: i64,
}

/// What the WAF concluded, beyond the human-readable reason.
#[derive(Debug, Clone, Default)]
pub struct Findings {
    pub score: i64,
    pub hits:  Vec<RuleHit>,
}

impl Findings {
    /// Fold another module's findings in. Scores add because the WAF's own
    /// threshold is a sum; hits accumulate so nothing that matched is lost.
    pub fn merge(&mut self, other: Findings) {
        self.score += other.score;
        self.hits.extend(other.hits);
    }

    /// The hits as JSON for storage, or None when nothing matched — so an
    /// ordinary request stores no column rather than an empty array.
    pub fn hits_json(&self) -> Option<String> {
        if self.hits.is_empty() {
            return None;
        }
        serde_json::to_string(&self.hits).ok()
    }
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
    Allow { alerts: Vec<Alert>, findings: Findings },
    /// Show a CAPTCHA challenge unless the client already has clearance.
    Challenge {
        reason:   String,
        alerts:   Vec<Alert>,
        findings: Findings,
    },
    /// Block the request. The chain was stopped by one module.
    Block {
        reason:   String,
        status:   StatusCode,
        alerts:   Vec<Alert>,
        findings: Findings,
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
        // Carried across modules so a request that is alerted on by one and
        // blocked by another still reports everything that matched.
        let mut findings = Findings::default();

        for module in &self.modules {
            match module.inspect(ctx).await {
                ModuleDecision::Pass => {}

                ModuleDecision::Alert { reason, findings: f } => {
                    tracing::debug!(
                        module = module.name(),
                        reason = %reason,
                        "module alert"
                    );
                    findings.merge(f);
                    alerts.push(Alert { module: module.name(), reason });
                }

                ModuleDecision::Challenge { reason, findings: f } => {
                    tracing::info!(
                        module = module.name(),
                        reason = %reason,
                        "request challenged"
                    );
                    findings.merge(f);
                    return PipelineVerdict::Challenge { reason, alerts, findings };
                }

                ModuleDecision::Drop { reason, status, findings: f } => {
                    tracing::info!(
                        module = module.name(),
                        reason = %reason,
                        status = status.as_u16(),
                        "request blocked"
                    );
                    findings.merge(f);
                    return PipelineVerdict::Block { reason, status, alerts, findings };
                }
            }
        }

        PipelineVerdict::Allow { alerts, findings }
    }
}

impl Default for Pipeline {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn findings_merge_across_modules() {
        // A request alerted on by one module and blocked by another must
        // report everything that matched, not only the last module's view.
        let mut a = Findings {
            score: 6,
            hits: vec![RuleHit { id: Some(920002), name: "double encoding".into(), score: 6 }],
        };
        a.merge(Findings {
            score: 8,
            hits: vec![RuleHit { id: Some(932012), name: "chaining".into(), score: 8 }],
        });
        assert_eq!(a.score, 14, "the threshold is a sum, so scores add");
        assert_eq!(a.hits.len(), 2);
    }

    #[test]
    fn nothing_matched_stores_nothing() {
        // An ordinary request is the overwhelming majority of rows; it should
        // not carry an empty array on every one of them.
        assert!(Findings::default().hits_json().is_none());
    }

    #[test]
    fn hits_round_trip_through_json() {
        // The traffic page parses this back out, so the shape has to survive.
        let f = Findings {
            score: 11,
            hits: vec![
                RuleHit { id: Some(932012), name: "RCE: chaining".into(), score: 8 },
                RuleHit { id: None, name: "a custom rule".into(), score: 3 },
            ],
        };
        let json = f.hits_json().expect("some hits");
        let back: Vec<RuleHit> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].id, Some(932012));
        assert_eq!(back[0].score, 8);
        // A custom rule has no catalogue number, and that must not become 0.
        assert_eq!(back[1].id, None);
    }
}
