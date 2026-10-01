// =========================================================
// modules/mod.rs — EasyWAF
// Inspection module pipeline.
//
// Each module receives a RequestContext and returns one of:
//   Pass      — nothing to say; continue with the next module
//   Alert     — something matched, but the request is allowed;
//               continue
//   Challenge — show a CAPTCHA; stop the chain
//   Drop      — block the request; stop the chain
//
// Modules run in order, and the first Challenge or Drop ends
// the chain. What every module found is carried forward, so
// the verdict reports all of it.
// =========================================================

pub mod generation;
pub mod geoip;
pub mod traffic;
pub mod waf;

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use bytes::Bytes;
use axum::http::HeaderMap;

// ─── RequestContext ───────────────────────────────────────

/// What the modules read about a request.
pub struct RequestContext {
    pub site_id:    i64,
    pub site_name:  String,
    pub client_ip:  IpAddr,
    pub path:       String,
    pub query:      Option<String>,
    pub headers:    HeaderMap,
    /// As much of the body as the rules inspect — see `proxy::inspection_limit`.
    pub body:       Bytes,
}

// ─── ModuleDecision ──────────────────────────────────────

/// Decision returned by a single module.
#[derive(Debug)]
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
/// why it decided what it did, and a false positive should be diagnosable from
/// the traffic row — not by enabling debug logging on a production proxy and
/// reproducing the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHit {
    /// The OWASP-style catalogue number, when the rule has one.
    pub id:    Option<i64>,
    pub name:  String,
    pub score: i64,
}

/// What a module would have done, when it did not do it.
///
/// A request that matches rules and is still allowed — because it stayed under
/// the threshold, or because the policy is DetectionOnly — must not leave a
/// traffic record indistinguishable from clean traffic: DetectionOnly exists to
/// show what enforcing would do.
///
/// Ordered by severity so `merge` can keep the strongest across modules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Detection {
    /// Rules matched, and the request was allowed on its merits — under the
    /// block threshold, in a policy that is enforcing.
    Observed,
    /// Enforcing would have challenged this request.
    WouldChallenge,
    /// Enforcing would have refused this request.
    WouldBlock,
}

impl Detection {
    /// The stored form. Kept short and stable: it goes in a database column
    /// and is matched on by the Traffic Monitor's filter.
    pub fn as_str(self) -> &'static str {
        match self {
            Detection::Observed       => "observed",
            Detection::WouldChallenge => "would_challenge",
            Detection::WouldBlock     => "would_block",
        }
    }
}

/// What the WAF concluded, beyond the human-readable reason.
#[derive(Debug, Clone, Default)]
pub struct Findings {
    pub score: i64,
    pub hits:  Vec<RuleHit>,
    /// What would have happened had the policy been enforcing. `None` on a
    /// request that was actually blocked or challenged — the verdict says so
    /// already — and on one where nothing matched.
    pub detection: Option<Detection>,
    /// Whether this counts towards Smart Protect: the rules refused the
    /// request, or would have in a policy that is only watching. A country
    /// refusal does not — that address is refused every time anyway.
    pub offence: bool,
}

impl Findings {
    /// Fold another module's findings in. Scores add because the WAF's own
    /// threshold is a sum; hits accumulate so nothing that matched is lost.
    pub fn merge(&mut self, other: Findings) {
        self.score += other.score;
        self.hits.extend(other.hits);
        // The strongest wins: if one module would only have observed and
        // another would have blocked, the request would have been blocked.
        self.detection = self.detection.max(other.detection);
        self.offence |= other.offence;
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

/// Why a module flagged a request it let through. The reasons of every alert
/// on an allowed request become its traffic row's reason.
#[derive(Debug, Clone)]
pub struct Alert {
    pub reason: String,
}

// ─── PipelineVerdict ─────────────────────────────────────

/// Final outcome after all modules have run.
#[derive(Debug)]
pub enum PipelineVerdict {
    /// Forward to upstream, with any alerts raised along the way.
    Allow { alerts: Vec<Alert>, findings: Findings },
    /// Show a CAPTCHA challenge unless the client already has clearance.
    Challenge {
        reason:   String,
        findings: Findings,
    },
    /// Block the request. The chain was stopped by one module.
    Block {
        reason:   String,
        status:   StatusCode,
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
                    alerts.push(Alert { reason });
                }

                ModuleDecision::Challenge { reason, findings: f } => {
                    tracing::info!(
                        module = module.name(),
                        reason = %reason,
                        "request challenged"
                    );
                    findings.merge(f);
                    return PipelineVerdict::Challenge { reason, findings };
                }

                ModuleDecision::Drop { reason, status, findings: f } => {
                    tracing::info!(
                        module = module.name(),
                        reason = %reason,
                        status = status.as_u16(),
                        "request blocked"
                    );
                    findings.merge(f);
                    return PipelineVerdict::Block { reason, status, findings };
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
            detection: Some(Detection::Observed),
            offence: false,
        };
        a.merge(Findings {
            score: 8,
            hits: vec![RuleHit { id: Some(932012), name: "chaining".into(), score: 8 }],
            detection: Some(Detection::WouldBlock),
            offence: false,
        });
        assert_eq!(a.score, 14, "the threshold is a sum, so scores add");
        assert_eq!(a.hits.len(), 2);
        assert_eq!(
            a.detection, Some(Detection::WouldBlock),
            "the strongest outcome wins: one module would only have watched, \
             the other would have refused"
        );
    }

    #[test]
    fn a_detection_never_weakens_on_merge() {
        // Order must not decide severity — merging in the other direction has
        // to reach the same answer.
        let mut a = Findings { detection: Some(Detection::WouldBlock), ..Findings::default() };
        a.merge(Findings { detection: Some(Detection::Observed), ..Findings::default() });
        assert_eq!(a.detection, Some(Detection::WouldBlock));

        let mut b = Findings::default();
        b.merge(Findings { detection: Some(Detection::Observed), ..Findings::default() });
        assert_eq!(b.detection, Some(Detection::Observed), "None must not outrank a detection");
    }

    #[test]
    fn the_stored_forms_are_distinct_and_stable() {
        // These strings go in a database column and are matched on by the
        // Traffic Monitor's filter, so a rename is a migration.
        assert_eq!(Detection::Observed.as_str(),       "observed");
        assert_eq!(Detection::WouldChallenge.as_str(), "would_challenge");
        assert_eq!(Detection::WouldBlock.as_str(),     "would_block");
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
            detection: None,
            offence: false,
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
