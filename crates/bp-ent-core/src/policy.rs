//! Admin governance: the LLM provider/model policy (with the optional
//! zero-data-retention rule) and approval gates for high-impact actions.

use crate::{audit, AuthKind, Error, Permission, Principal, Result, Role, TenantId, Tx};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

// ============================================================== LLM policy

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmProvider {
    Anthropic,
    Openai,
    Google,
    AwsBedrock,
    AzureOpenai,
    SelfHosted,
}

/// One allowed provider and which of its models may be used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderRule {
    pub provider: LlmProvider,
    /// Exact model ids, or prefixes ending in `*` (`claude-*`). `["*"]` = any.
    pub models: Vec<String>,
    /// The org's account with this provider has a zero-data-retention
    /// agreement. Asserted by the admin; it is the customer's contract.
    #[serde(default)]
    pub zdr: bool,
    /// For self-hosted / Azure endpoints: the only base URL requests may go to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LlmPolicy {
    pub providers: Vec<ProviderRule>,
    /// Optional ZDR mode: when on, only providers marked `zdr` may be used.
    #[serde(default)]
    pub zdr_required: bool,
    /// Whether agents may connect to MCP servers outside the built-in set
    /// without going through the `enable_external_mcp` approval gate.
    #[serde(default)]
    pub allow_external_mcp: bool,
    /// Monthly LLM budget in cents; `None` = no cap. Spending past it trips
    /// the `spend_over_budget` gate.
    #[serde(default)]
    pub monthly_budget_cents: Option<i64>,
}

impl Default for LlmPolicy {
    /// A new org can use the mainstream hosted providers; nothing is marked
    /// ZDR and self-hosted endpoints must be added explicitly.
    fn default() -> Self {
        let any = |provider| ProviderRule { provider, models: vec!["*".into()], zdr: false, base_url: None };
        Self {
            providers: vec![any(LlmProvider::Anthropic), any(LlmProvider::Openai), any(LlmProvider::Google)],
            zdr_required: false,
            allow_external_mcp: false,
            monthly_budget_cents: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum LlmDecision {
    Allow,
    Deny { reason: DenyReason },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    ProviderNotAllowed,
    ModelNotAllowed,
    ZdrRequired,
    EndpointNotAllowed,
}

fn model_matches(pattern: &str, model: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => model.starts_with(prefix),
        None => pattern == model,
    }
}

impl LlmPolicy {
    /// May this org send a request to `provider`/`model` (at `base_url`, for
    /// providers that have one)?
    pub fn evaluate(&self, provider: LlmProvider, model: &str, base_url: Option<&str>) -> LlmDecision {
        let deny = |reason| LlmDecision::Deny { reason };
        let Some(rule) = self.providers.iter().find(|r| r.provider == provider) else {
            return deny(DenyReason::ProviderNotAllowed);
        };
        if self.zdr_required && !rule.zdr {
            return deny(DenyReason::ZdrRequired);
        }
        if !rule.models.iter().any(|p| model_matches(p, model)) {
            return deny(DenyReason::ModelNotAllowed);
        }
        match (&rule.base_url, base_url) {
            (Some(allowed), Some(got)) if allowed.trim_end_matches('/') != got.trim_end_matches('/') => {
                return deny(DenyReason::EndpointNotAllowed)
            }
            (Some(_), None) => return deny(DenyReason::EndpointNotAllowed),
            // Self-hosted with no pinned endpoint would let a caller pick any host.
            (None, _) if provider == LlmProvider::SelfHosted => return deny(DenyReason::EndpointNotAllowed),
            _ => {}
        }
        LlmDecision::Allow
    }

    pub fn validate(&self) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for r in &self.providers {
            if !seen.insert(r.provider) {
                return Err(Error::invalid("a provider is listed twice"));
            }
            if r.models.is_empty() || r.models.len() > 200 {
                return Err(Error::invalid("each provider needs between 1 and 200 model patterns"));
            }
            for m in &r.models {
                let body = m.strip_suffix('*').unwrap_or(m);
                if m.is_empty() || m.len() > 200 || body.contains('*') {
                    return Err(Error::invalid("model patterns are exact ids or a prefix ending in *"));
                }
            }
            if let Some(u) = &r.base_url {
                let ok = url::Url::parse(u).map(|u| u.scheme() == "https" && u.host_str().is_some()).unwrap_or(false);
                if !ok {
                    return Err(Error::invalid("provider base_url must be an https URL"));
                }
            }
            if r.provider == LlmProvider::SelfHosted && r.base_url.is_none() {
                return Err(Error::invalid("a self-hosted provider needs a base_url"));
            }
        }
        if self.zdr_required && !self.providers.iter().any(|r| r.zdr) {
            return Err(Error::invalid("ZDR is required but no provider is marked ZDR; nothing could be used"));
        }
        if matches!(self.monthly_budget_cents, Some(c) if c < 0) {
            return Err(Error::invalid("budget cannot be negative"));
        }
        Ok(())
    }
}

// ========================================================== approval gates

/// A high-impact action an agent (or user) is about to take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateKind {
    PlaceOrder { amount_cents: i64 },
    ModifyReleasedPart,
    ModifyReleasedBoard,
    EnableExternalMcp,
    SpendOverBudget { amount_cents: i64 },
}

impl GateKind {
    pub fn name(&self) -> &'static str {
        match self {
            GateKind::PlaceOrder { .. } => "place_order",
            GateKind::ModifyReleasedPart => "modify_released_part",
            GateKind::ModifyReleasedBoard => "modify_released_board",
            GateKind::EnableExternalMcp => "enable_external_mcp",
            GateKind::SpendOverBudget { .. } => "spend_over_budget",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GateRule {
    pub enabled: bool,
    /// For amount gates: only amounts above this need approval. `None` = always.
    #[serde(default)]
    pub threshold_cents: Option<i64>,
    /// Roles that may approve.
    pub approvers: Vec<Role>,
    /// Apply only to agents/tokens (true) or to people in the browser as well (false).
    #[serde(default)]
    pub agents_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalGates {
    pub place_order: GateRule,
    pub modify_released_part: GateRule,
    pub modify_released_board: GateRule,
    pub enable_external_mcp: GateRule,
    pub spend_over_budget: GateRule,
    /// Let the requester approve their own request (single-admin orgs).
    /// Off by default: approvals are four-eyes.
    #[serde(default)]
    pub allow_self_approval: bool,
    /// Hours a pending or approved-but-unused request stays valid.
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: u32,
}

fn default_ttl_hours() -> u32 {
    72
}

impl Default for ApprovalGates {
    /// Everything gated by default; an admin loosens it deliberately.
    fn default() -> Self {
        let rule = |approvers: &[Role]| GateRule { enabled: true, threshold_cents: None, approvers: approvers.to_vec(), agents_only: false };
        Self {
            place_order: rule(&[Role::OrgAdmin, Role::Purchasing]),
            modify_released_part: rule(&[Role::OrgAdmin, Role::Librarian]),
            modify_released_board: rule(&[Role::OrgAdmin]),
            enable_external_mcp: rule(&[Role::OrgAdmin]),
            spend_over_budget: rule(&[Role::OrgAdmin]),
            allow_self_approval: false,
            ttl_hours: default_ttl_hours(),
        }
    }
}

impl ApprovalGates {
    pub const GATES: [&'static str; 5] =
        ["place_order", "modify_released_part", "modify_released_board", "enable_external_mcp", "spend_over_budget"];

    pub fn rule_mut(&mut self, gate: &str) -> Option<&mut GateRule> {
        Some(match gate {
            "place_order" => &mut self.place_order,
            "modify_released_part" => &mut self.modify_released_part,
            "modify_released_board" => &mut self.modify_released_board,
            "enable_external_mcp" => &mut self.enable_external_mcp,
            "spend_over_budget" => &mut self.spend_over_budget,
            _ => return None,
        })
    }

    pub fn rule(&self, gate: &str) -> Option<&GateRule> {
        Some(match gate {
            "place_order" => &self.place_order,
            "modify_released_part" => &self.modify_released_part,
            "modify_released_board" => &self.modify_released_board,
            "enable_external_mcp" => &self.enable_external_mcp,
            "spend_over_budget" => &self.spend_over_budget,
            _ => return None,
        })
    }

    /// Does this action, by this kind of caller, need an approval?
    pub fn needs_approval(&self, gate: &GateKind, auth: AuthKind) -> bool {
        let rule = self.rule(gate.name()).expect("every GateKind has a rule");
        if !rule.enabled || (rule.agents_only && auth == AuthKind::Session) {
            return false;
        }
        match (gate, rule.threshold_cents) {
            (GateKind::PlaceOrder { amount_cents } | GateKind::SpendOverBudget { amount_cents }, Some(t)) => *amount_cents > t,
            _ => true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        for r in [&self.place_order, &self.modify_released_part, &self.modify_released_board, &self.enable_external_mcp, &self.spend_over_budget] {
            if r.enabled && r.approvers.is_empty() {
                return Err(Error::invalid("an enabled gate needs at least one approver role"));
            }
            if r.approvers.contains(&Role::ExternalReviewer) {
                return Err(Error::invalid("external reviewers cannot be approvers"));
            }
            if matches!(r.threshold_cents, Some(t) if t < 0) {
                return Err(Error::invalid("threshold cannot be negative"));
            }
        }
        if !(1..=24 * 90).contains(&self.ttl_hours) {
            return Err(Error::invalid("ttl_hours must be between 1 and 2160"));
        }
        Ok(())
    }
}

// ------------------------------------------------------------- persistence

pub(crate) async fn store_defaults(tx: &mut Tx, tenant: TenantId) -> Result<()> {
    sqlx::query("INSERT INTO tenant_settings (tenant_id, llm_policy, approval_gates) VALUES ($1, $2, $3) ON CONFLICT (tenant_id) DO NOTHING")
        .bind(tenant.0)
        .bind(sqlx::types::Json(LlmPolicy::default()))
        .bind(sqlx::types::Json(ApprovalGates::default()))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn load(tx: &mut Tx, tenant: TenantId) -> Result<(LlmPolicy, ApprovalGates)> {
    let row = sqlx::query("SELECT llm_policy, approval_gates FROM tenant_settings WHERE tenant_id = $1")
        .bind(tenant.0)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(row) = row else {
        return Ok((LlmPolicy::default(), ApprovalGates::default()));
    };
    // A stored policy that no longer parses must not silently become the
    // (looser) default.
    let llm: serde_json::Value = row.get("llm_policy");
    let gates: serde_json::Value = row.get("approval_gates");
    Ok((
        serde_json::from_value(llm).map_err(|e| Error::internal(anyhow::anyhow!("stored LLM policy is unreadable: {e}")))?,
        serde_json::from_value(gates).map_err(|e| Error::internal(anyhow::anyhow!("stored approval gates are unreadable: {e}")))?,
    ))
}

pub async fn load_llm_policy(tx: &mut Tx, tenant: TenantId) -> Result<LlmPolicy> {
    Ok(load(tx, tenant).await?.0)
}

pub async fn save_llm_policy(tx: &mut Tx, admin: &Principal, policy: &LlmPolicy) -> Result<()> {
    admin.require(Permission::AdminManage)?;
    policy.validate()?;
    let before = load(tx, admin.tenant_id).await?.0;
    store_defaults(tx, admin.tenant_id).await?;
    sqlx::query("UPDATE tenant_settings SET llm_policy = $2, updated_at = now() WHERE tenant_id = $1")
        .bind(admin.tenant_id.0)
        .bind(sqlx::types::Json(policy))
        .execute(&mut **tx)
        .await?;
    audit::append(tx, admin, "llm_policy.updated", "tenant_settings:llm_policy", serde_json::json!({ "before": before, "after": policy })).await?;
    Ok(())
}

pub async fn save_approval_gates(tx: &mut Tx, admin: &Principal, gates: &ApprovalGates) -> Result<()> {
    admin.require(Permission::AdminManage)?;
    // Loosening the gates is itself something an agent must not do.
    admin.require_interactive()?;
    gates.validate()?;
    let before = load(tx, admin.tenant_id).await?.1;
    store_defaults(tx, admin.tenant_id).await?;
    sqlx::query("UPDATE tenant_settings SET approval_gates = $2, updated_at = now() WHERE tenant_id = $1")
        .bind(admin.tenant_id.0)
        .bind(sqlx::types::Json(gates))
        .execute(&mut **tx)
        .await?;
    audit::append(tx, admin, "approval_gates.updated", "tenant_settings:approval_gates", serde_json::json!({ "before": before, "after": gates })).await?;
    Ok(())
}

// ------------------------------------------------------- approval requests

/// Result of asking whether a gated action may proceed now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Approval {
    /// The gate is off (or does not apply to this caller / amount). Proceed.
    NotRequired,
    /// A matching approval existed and has now been used up. Proceed.
    Approved { request_id: Uuid },
    /// A request is waiting for an approver. Do not proceed; tell the caller.
    Pending { request_id: Uuid },
    /// The matching request was rejected. Do not proceed.
    Rejected { request_id: Uuid, reason: Option<String> },
}

impl Approval {
    pub fn may_proceed(&self) -> bool {
        matches!(self, Approval::NotRequired | Approval::Approved { .. })
    }
}

fn payload_hash(gate: &str, subject: &str, summary: &serde_json::Value) -> Vec<u8> {
    let mut h = Sha256::new();
    for part in [gate.as_bytes(), subject.as_bytes(), summary.to_string().as_bytes()] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().to_vec()
}

/// Gate a high-impact action. Call it inside the transaction that performs
/// the action, immediately before doing it:
///
/// ```ignore
/// match policy::require_approval(&mut tx, &principal, GateKind::PlaceOrder { amount_cents }, &format!("order:{id}"), summary).await? {
///     a if a.may_proceed() => { /* place the order, commit */ }
///     Approval::Pending { request_id } => { tx.commit().await?; /* 202 + request_id */ }
///     _ => { /* refused */ }
/// }
/// ```
///
/// `subject` identifies the thing acted on; `summary` is what the approver
/// sees (no secrets: it is stored in clear). The approval is bound to the
/// hash of both: if the order changes after approval, the old approval no
/// longer matches and a new request is opened. An approval is single-use.
pub async fn require_approval(
    tx: &mut Tx,
    principal: &Principal,
    gate: GateKind,
    subject: &str,
    summary: serde_json::Value,
) -> Result<Approval> {
    let tenant = principal.tenant_id;
    let (_, gates) = load(tx, tenant).await?;
    if !gates.needs_approval(&gate, principal.auth) {
        return Ok(Approval::NotRequired);
    }
    let name = gate.name();
    let hash = payload_hash(name, subject, &summary);

    sqlx::query("UPDATE approval_requests SET status = 'expired' WHERE tenant_id = $1 AND status IN ('pending', 'approved') AND expires_at < now()")
        .bind(tenant.0)
        .execute(&mut **tx)
        .await?;

    let existing = sqlx::query(
        "SELECT id, status, reason FROM approval_requests \
         WHERE tenant_id = $1 AND gate = $2 AND subject = $3 AND payload_hash = $4 \
           AND status IN ('pending', 'approved', 'rejected') \
         ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
    )
    .bind(tenant.0)
    .bind(name)
    .bind(subject)
    .bind(&hash)
    .fetch_optional(&mut **tx)
    .await?;

    if let Some(r) = existing {
        let id: Uuid = r.get("id");
        match r.get::<String, _>("status").as_str() {
            "approved" => {
                sqlx::query("UPDATE approval_requests SET status = 'consumed' WHERE tenant_id = $1 AND id = $2")
                    .bind(tenant.0)
                    .bind(id)
                    .execute(&mut **tx)
                    .await?;
                audit::append(tx, principal, "approval.consumed", &format!("approval:{id}"), serde_json::json!({ "gate": name, "subject": subject })).await?;
                return Ok(Approval::Approved { request_id: id });
            }
            "pending" => return Ok(Approval::Pending { request_id: id }),
            _ => return Ok(Approval::Rejected { request_id: id, reason: r.get("reason") }),
        }
    }

    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO approval_requests (id, tenant_id, gate, subject, payload_hash, summary, requested_by, requested_via, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(hours => $9))",
    )
    .bind(id)
    .bind(tenant.0)
    .bind(name)
    .bind(subject)
    .bind(&hash)
    .bind(&summary)
    .bind(principal.user_id.0)
    .bind(principal.auth.as_str())
    .bind(gates.ttl_hours as i32)
    .execute(&mut **tx)
    .await?;
    audit::append(tx, principal, "approval.requested", &format!("approval:{id}"), serde_json::json!({ "gate": name, "subject": subject })).await?;
    Ok(Approval::Pending { request_id: id })
}

/// Approve or reject a pending request. Needs a browser session (a person,
/// not a token), a role the gate lists as approver, and, unless the org
/// turned self-approval on, someone other than the requester.
pub async fn decide(tx: &mut Tx, approver: &Principal, request_id: Uuid, approve: bool, reason: Option<&str>) -> Result<()> {
    approver.require_interactive()?;
    let tenant = approver.tenant_id;
    let row = sqlx::query("SELECT gate, subject, status, requested_by, expires_at < now() AS expired FROM approval_requests WHERE tenant_id = $1 AND id = $2 FOR UPDATE")
        .bind(tenant.0)
        .bind(request_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(Error::NotFound)?;
    let gate: String = row.get("gate");
    let (_, gates) = load(tx, tenant).await?;
    let rule = gates.rule(&gate).ok_or(Error::Forbidden)?;
    if !rule.approvers.contains(&approver.role) {
        return Err(Error::Forbidden);
    }
    if row.get::<Uuid, _>("requested_by") == approver.user_id.0 && !gates.allow_self_approval {
        return Err(Error::Forbidden);
    }
    if row.get::<String, _>("status") != "pending" || row.get::<bool, _>("expired") {
        return Err(Error::conflict("request is no longer pending"));
    }
    if matches!(reason, Some(r) if r.len() > 2000) {
        return Err(Error::invalid("reason is too long"));
    }
    sqlx::query("UPDATE approval_requests SET status = $3, decided_by = $4, decided_at = now(), reason = $5 WHERE tenant_id = $1 AND id = $2")
        .bind(tenant.0)
        .bind(request_id)
        .bind(if approve { "approved" } else { "rejected" })
        .bind(approver.user_id.0)
        .bind(reason)
        .execute(&mut **tx)
        .await?;
    audit::append(
        tx,
        approver,
        if approve { "approval.approved" } else { "approval.rejected" },
        &format!("approval:{request_id}"),
        serde_json::json!({ "gate": gate, "subject": row.get::<String, _>("subject") }),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(provider: LlmProvider, models: &[&str], zdr: bool) -> ProviderRule {
        ProviderRule { provider, models: models.iter().map(|s| s.to_string()).collect(), zdr, base_url: None }
    }

    #[test]
    fn provider_and_model_allowlist() {
        let p = LlmPolicy {
            providers: vec![rule(LlmProvider::Anthropic, &["claude-*"], false), rule(LlmProvider::Openai, &["gpt-x"], false)],
            ..LlmPolicy::default()
        };
        assert_eq!(p.evaluate(LlmProvider::Anthropic, "claude-opus", None), LlmDecision::Allow);
        assert_eq!(p.evaluate(LlmProvider::Openai, "gpt-x", None), LlmDecision::Allow);
        assert_eq!(p.evaluate(LlmProvider::Openai, "gpt-x-mini", None), LlmDecision::Deny { reason: DenyReason::ModelNotAllowed });
        assert_eq!(p.evaluate(LlmProvider::Google, "gemini", None), LlmDecision::Deny { reason: DenyReason::ProviderNotAllowed });
    }

    #[test]
    fn zdr_toggle_restricts_to_zdr_providers() {
        let mut p = LlmPolicy {
            providers: vec![rule(LlmProvider::Anthropic, &["*"], true), rule(LlmProvider::Openai, &["*"], false)],
            ..LlmPolicy::default()
        };
        assert_eq!(p.evaluate(LlmProvider::Openai, "m", None), LlmDecision::Allow);
        p.zdr_required = true;
        assert_eq!(p.evaluate(LlmProvider::Openai, "m", None), LlmDecision::Deny { reason: DenyReason::ZdrRequired });
        assert_eq!(p.evaluate(LlmProvider::Anthropic, "m", None), LlmDecision::Allow);
        assert!(p.validate().is_ok());
        p.providers[0].zdr = false;
        assert!(p.validate().is_err(), "ZDR on with no ZDR provider locks everyone out");
    }

    #[test]
    fn self_hosted_endpoint_is_pinned() {
        let mut r = rule(LlmProvider::SelfHosted, &["*"], true);
        r.base_url = Some("https://llm.corp.example/v1".into());
        let p = LlmPolicy { providers: vec![r], ..LlmPolicy::default() };
        assert_eq!(p.evaluate(LlmProvider::SelfHosted, "m", Some("https://llm.corp.example/v1/")), LlmDecision::Allow);
        assert_eq!(p.evaluate(LlmProvider::SelfHosted, "m", Some("https://evil.example/v1")), LlmDecision::Deny { reason: DenyReason::EndpointNotAllowed });
        assert_eq!(p.evaluate(LlmProvider::SelfHosted, "m", None), LlmDecision::Deny { reason: DenyReason::EndpointNotAllowed });
        let p = LlmPolicy { providers: vec![rule(LlmProvider::SelfHosted, &["*"], false)], ..LlmPolicy::default() };
        assert!(p.validate().is_err());
        assert_ne!(p.evaluate(LlmProvider::SelfHosted, "m", Some("https://x.example")), LlmDecision::Allow);
    }

    #[test]
    fn validation_rejects_bad_patterns() {
        let bad = |models: &[&str]| LlmPolicy { providers: vec![rule(LlmProvider::Openai, models, false)], ..LlmPolicy::default() }.validate().is_err();
        assert!(bad(&[]));
        assert!(bad(&["a*b"]));
        assert!(bad(&[""]));
        assert!(!bad(&["*"]));
        assert!(LlmPolicy::default().validate().is_ok());
        assert!(ApprovalGates::default().validate().is_ok());
    }

    #[test]
    fn default_policy_round_trips_json() {
        let p = LlmPolicy::default();
        let back: LlmPolicy = serde_json::from_value(serde_json::to_value(&p).unwrap()).unwrap();
        assert_eq!(p, back);
        let g = ApprovalGates::default();
        let back: ApprovalGates = serde_json::from_value(serde_json::to_value(&g).unwrap()).unwrap();
        assert_eq!(g, back);
    }

    #[test]
    fn gates_default_on_with_threshold_and_agent_scoping() {
        let mut g = ApprovalGates::default();
        assert!(g.needs_approval(&GateKind::PlaceOrder { amount_cents: 1 }, AuthKind::Session));
        assert!(g.needs_approval(&GateKind::EnableExternalMcp, AuthKind::UserToken));

        g.place_order.threshold_cents = Some(50_000);
        assert!(!g.needs_approval(&GateKind::PlaceOrder { amount_cents: 50_000 }, AuthKind::UserToken));
        assert!(g.needs_approval(&GateKind::PlaceOrder { amount_cents: 50_001 }, AuthKind::UserToken));

        g.modify_released_part.agents_only = true;
        assert!(!g.needs_approval(&GateKind::ModifyReleasedPart, AuthKind::Session));
        assert!(g.needs_approval(&GateKind::ModifyReleasedPart, AuthKind::UserToken));

        g.modify_released_board.enabled = false;
        assert!(!g.needs_approval(&GateKind::ModifyReleasedBoard, AuthKind::UserToken));
    }

    #[test]
    fn gate_validation() {
        let mut g = ApprovalGates::default();
        g.place_order.approvers.clear();
        assert!(g.validate().is_err());
        let mut g = ApprovalGates::default();
        g.place_order.approvers.push(Role::ExternalReviewer);
        assert!(g.validate().is_err());
    }

    #[test]
    fn approval_is_bound_to_payload() {
        let a = payload_hash("place_order", "order:1", &serde_json::json!({ "total": 100 }));
        let b = payload_hash("place_order", "order:1", &serde_json::json!({ "total": 9999 }));
        let c = payload_hash("place_order", "order:2", &serde_json::json!({ "total": 100 }));
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
