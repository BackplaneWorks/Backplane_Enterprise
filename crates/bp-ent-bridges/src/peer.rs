//! Scoped External Agent Peer (MCP / A2A Sandbox).
//!
//! External bots (Grok, Dots, n8n, Slack/Teams/Discord agents) operate inside a
//! strict sandbox:
//! - Only `boards:read` and `boards:comment` may be granted (deny by default).
//! - Zero shell access, zero private HTTP library access, zero secret access,
//!   zero Boat VM / billing / admin permissions.
//! - Inbound text is always quarantined as `trust_level = "untrusted_external"`
//!   and is never executed as LLM instructions.
//! - Any proposed state change is routed through `bp_ent_core::policy::require_approval`
//!   so a human approver must decide it.

use crate::model::sanitize_external_text;
use crate::sealed;
use bp_ent_core::policy::{self, Approval, GateKind};
use bp_ent_core::rbac::Scopes;
use bp_ent_core::{audit, AuthKind, Error, Permission, Principal, Result, Role, TenantId, Tx, UserId};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

/// Maximum set of permissions an external agent peer can ever hold.
pub const ALLOWED_PEER_PERMISSIONS: &[Permission] = &[
    Permission::BoardsRead,
    Permission::BoardsComment,
];

/// Validate admin-supplied `peer_scopes` against the strict allowlist.
pub fn validate_peer_scopes(raw: &[String]) -> Result<Vec<Permission>> {
    let mut out = Vec::new();
    for s in raw {
        let p = Permission::from_scope(s)
            .ok_or_else(|| Error::invalid(format!("unknown peer scope {s:?}")))?;
        if !ALLOWED_PEER_PERMISSIONS.contains(&p) {
            return Err(Error::invalid(format!(
                "external peer scope {s:?} is forbidden (allowed: boards:read, boards:comment)"
            )));
        }
        if !out.contains(&p) {
            out.push(p);
        }
    }
    Ok(out)
}

#[derive(Clone, Debug)]
pub struct ExternalPeerPrincipal {
    pub tenant_id: TenantId,
    pub bridge_id: Uuid,
    pub bridge_name: String,
    pub owner_user_id: UserId,
    pub allowed: Vec<Permission>,
}

impl ExternalPeerPrincipal {
    pub fn from_scopes(
        tenant_id: TenantId,
        bridge_id: Uuid,
        bridge_name: String,
        owner_user_id: UserId,
        raw_scopes: &[String],
    ) -> Result<Self> {
        let allowed = validate_peer_scopes(raw_scopes)?;
        Ok(Self {
            tenant_id,
            bridge_id,
            bridge_name,
            owner_user_id,
            allowed,
        })
    }

    pub fn can(&self, p: Permission) -> bool {
        ALLOWED_PEER_PERMISSIONS.contains(&p) && self.allowed.contains(&p)
    }

    pub fn require(&self, p: Permission) -> Result<()> {
        if self.can(p) {
            Ok(())
        } else {
            Err(Error::Forbidden)
        }
    }

    /// Lower-privilege `bp_ent_core::Principal` for audit + approval-gate calls.
    /// Role is strictly `ExternalReviewer` and `AuthKind::DeviceToken` (non-interactive).
    pub fn to_core_principal(&self) -> Principal {
        Principal {
            tenant_id: self.tenant_id,
            user_id: self.owner_user_id,
            role: Role::ExternalReviewer,
            email: format!("bridge-peer+{}@external.invalid", self.bridge_id),
            auth: AuthKind::DeviceToken,
            scopes: Scopes::Only(self.allowed.clone()),
            token_id: self.bridge_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct PeerRpcRequest {
    #[serde(default = "default_jsonrpc")]
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

fn default_jsonrpc() -> String {
    "2.0".to_string()
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<PeerRpcError>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerRpcError {
    pub code: i32,
    pub message: String,
}

/// Dispatch an authenticated & replay-checked MCP/A2A JSON-RPC call inside the
/// tenant transaction.
pub async fn handle_peer_rpc(
    ctx: &bp_ent_core::AppCtx,
    tx: &mut Tx,
    peer: &ExternalPeerPrincipal,
    delivery_row_id: Uuid,
    req: PeerRpcRequest,
) -> Result<PeerRpcResponse> {
    if req.jsonrpc != "2.0" {
        return Err(Error::invalid("jsonrpc must be '2.0'"));
    }
    let actor = format!("bridge:{}", peer.bridge_id);
    match req.method.as_str() {
        "agent/card" => {
            let scopes: Vec<&'static str> = peer.allowed.iter().map(|p| p.scope()).collect();
            audit::append_system(
                tx,
                peer.tenant_id,
                &actor,
                "bridge.peer.card",
                &format!("bridge:{}", peer.bridge_id),
                json!({ "scopes": scopes }),
            )
            .await?;
            Ok(PeerRpcResponse {
                jsonrpc: "2.0",
                id: req.id,
                result: Some(json!({
                    "name": peer.bridge_name,
                    "protocol": "backplane-a2a-v1",
                    "sandboxed": true,
                    "trustLevel": "untrusted_external",
                    "allowedScopes": scopes,
                    "restrictions": {
                        "shell": false,
                        "httplib": false,
                        "secrets": false,
                        "vmUse": false,
                        "orders": false,
                        "approvalRequiredForMutations": true
                    }
                })),
                error: None,
            })
        }
        "tools/list" => {
            let mut tools = Vec::new();
            if peer.can(Permission::BoardsRead) {
                tools.push(json!({
                    "name": "boards.list_summary",
                    "description": "Read non-sensitive board metadata summaries.",
                    "requiredScope": "boards:read"
                }));
                tools.push(json!({
                    "name": "boards.read_comments",
                    "description": "Read quarantined comments for this bridge.",
                    "requiredScope": "boards:read"
                }));
            }
            if peer.can(Permission::BoardsComment) {
                tools.push(json!({
                    "name": "boards.post_comment",
                    "description": "Post a quarantined external review comment (untrusted_external).",
                    "requiredScope": "boards:comment"
                }));
                tools.push(json!({
                    "name": "room.post_reply",
                    "description": "Post a quarantined reply into a room/thread.",
                    "requiredScope": "boards:comment"
                }));
                tools.push(json!({
                    "name": "action.propose",
                    "description": "Submit a proposal to the human approval gate queue (never executes directly).",
                    "requiredScope": "boards:comment"
                }));
            }
            audit::append_system(
                tx,
                peer.tenant_id,
                &actor,
                "bridge.peer.tools_list",
                &format!("bridge:{}", peer.bridge_id),
                json!({ "count": tools.len() }),
            )
            .await?;
            Ok(PeerRpcResponse {
                jsonrpc: "2.0",
                id: req.id,
                result: Some(json!({ "tools": tools })),
                error: None,
            })
        }
        "tools/call" => {
            let tool_name = req
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::invalid("params.name is required"))?;
            let args = req.params.get("arguments").cloned().unwrap_or_else(|| json!({}));

            match tool_name {
                "boards.list_summary" => {
                    peer.require(Permission::BoardsRead)?;
                    audit::append_system(
                        tx,
                        peer.tenant_id,
                        &actor,
                        "bridge.peer.read",
                        "boards:summary",
                        json!({ "tool": tool_name }),
                    )
                    .await?;
                    Ok(PeerRpcResponse {
                        jsonrpc: "2.0",
                        id: req.id,
                        result: Some(json!({
                            "tenantId": peer.tenant_id,
                            "scope": "boards:read",
                            "note": "Read-only external peer view; private HTTP library and secrets excluded."
                        })),
                        error: None,
                    })
                }
                "boards.read_comments" => {
                    peer.require(Permission::BoardsRead)?;
                    let rows = sqlx::query(
                        "SELECT id, external_actor, channel_ref, event_type, trust_level, body_sealed, created_at \
                         FROM bridge_messages WHERE tenant_id = $1 AND bridge_id = $2 ORDER BY created_at DESC LIMIT 20",
                    )
                    .bind(peer.tenant_id.0)
                    .bind(peer.bridge_id)
                    .fetch_all(&mut **tx)
                    .await?;

                    use sqlx::Row;
                    let mut items = Vec::with_capacity(rows.len());
                    for r in rows {
                        let msg_id: Uuid = r.get("id");
                        let sealed_body: Vec<u8> = r.get("body_sealed");
                        let aad = sealed::aad("bridge_messages", msg_id, "body");
                        let body = sealed::open_str(ctx, peer.tenant_id, &aad, &sealed_body).await?;
                        items.push(json!({
                            "id": msg_id,
                            "externalActor": r.get::<String, _>("external_actor"),
                            "channelRef": r.get::<String, _>("channel_ref"),
                            "eventType": r.get::<String, _>("event_type"),
                            "trustLevel": r.get::<String, _>("trust_level"),
                            "text": body,
                        }));
                    }
                    audit::append_system(
                        tx,
                        peer.tenant_id,
                        &actor,
                        "bridge.peer.read_comments",
                        &format!("bridge:{}", peer.bridge_id),
                        json!({ "returned": items.len() }),
                    )
                    .await?;
                    Ok(PeerRpcResponse {
                        jsonrpc: "2.0",
                        id: req.id,
                        result: Some(json!({ "comments": items })),
                        error: None,
                    })
                }
                "boards.post_comment" | "room.post_reply" => {
                    peer.require(Permission::BoardsComment)?;
                    let raw_text = args
                        .get("text")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| Error::invalid("arguments.text is required"))?;
                    let channel_ref = sanitize_external_text(
                        args.get("target")
                            .or_else(|| args.get("boardId"))
                            .or_else(|| args.get("roomId"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("general"),
                        200,
                    );
                    let ext_actor = sanitize_external_text(
                        args.get("actor")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&peer.bridge_name),
                        200,
                    );
                    let sanitized = sanitize_external_text(raw_text, 4000);
                    let msg_id = Uuid::new_v4();
                    let aad = sealed::aad("bridge_messages", msg_id, "body");
                    let body_sealed = sealed::seal_str(ctx, peer.tenant_id, &aad, &sanitized).await?;

                    sqlx::query(
                        "INSERT INTO bridge_messages \
                         (id, tenant_id, bridge_id, delivery_id, external_actor, channel_ref, event_type, trust_level, body_sealed) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, 'untrusted_external', $8)",
                    )
                    .bind(msg_id)
                    .bind(peer.tenant_id.0)
                    .bind(peer.bridge_id)
                    .bind(delivery_row_id)
                    .bind(&ext_actor)
                    .bind(&channel_ref)
                    .bind(tool_name)
                    .bind(&body_sealed)
                    .execute(&mut **tx)
                    .await?;

                    audit::append_system(
                        tx,
                        peer.tenant_id,
                        &actor,
                        "bridge.peer.comment_quarantined",
                        &format!("bridge_message:{msg_id}"),
                        json!({
                            "tool": tool_name,
                            "channelRef": channel_ref,
                            "trustLevel": "untrusted_external"
                        }),
                    )
                    .await?;

                    Ok(PeerRpcResponse {
                        jsonrpc: "2.0",
                        id: req.id,
                        result: Some(json!({
                            "messageId": msg_id,
                            "trustLevel": "untrusted_external",
                            "sanitizedText": sanitized,
                        })),
                        error: None,
                    })
                }
                "action.propose" => {
                    peer.require(Permission::BoardsComment)?;
                    let summary_raw = args
                        .get("summary")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| Error::invalid("arguments.summary is required"))?;
                    let subject = sanitize_external_text(
                        args.get("subject")
                            .and_then(|v| v.as_str())
                            .unwrap_or("board:proposed"),
                        120,
                    );
                    let sanitized_summary = sanitize_external_text(summary_raw, 1000);
                    let core_principal = peer.to_core_principal();
                    let approval = policy::require_approval(
                        tx,
                        &core_principal,
                        GateKind::ModifyReleasedBoard,
                        &subject,
                        json!({
                            "source": "external_peer",
                            "bridgeId": peer.bridge_id,
                            "trustLevel": "untrusted_external",
                            "summary": sanitized_summary,
                        }),
                    )
                    .await?;

                    let (status_str, request_id) = match approval {
                        Approval::Pending { request_id } => ("pending_approval", Some(request_id)),
                        Approval::Rejected { request_id, .. } => ("rejected", Some(request_id)),
                        Approval::Approved { request_id } => ("approved", Some(request_id)),
                        Approval::NotRequired => ("not_required", None),
                    };

                    audit::append_system(
                        tx,
                        peer.tenant_id,
                        &actor,
                        "bridge.peer.action_proposed",
                        &subject,
                        json!({ "status": status_str, "approvalRequestId": request_id }),
                    )
                    .await?;

                    Ok(PeerRpcResponse {
                        jsonrpc: "2.0",
                        id: req.id,
                        result: Some(json!({
                            "status": status_str,
                            "approvalRequestId": request_id,
                            "trustLevel": "untrusted_external"
                        })),
                        error: None,
                    })
                }
                other => {
                    // Explicit deny-by-default for shell/httplib/vm/secrets/admin/orders tools.
                    audit::append_system(
                        tx,
                        peer.tenant_id,
                        &actor,
                        "bridge.peer.denied",
                        other,
                        json!({ "reason": "tool_not_in_sandbox_allowlist" }),
                    )
                    .await?;
                    Err(Error::Forbidden)
                }
            }
        }
        other => {
            audit::append_system(
                tx,
                peer.tenant_id,
                &actor,
                "bridge.peer.denied",
                other,
                json!({ "reason": "method_not_allowed" }),
            )
            .await?;
            Err(Error::Forbidden)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_principal_denies_all_privileged_permissions() {
        let peer = ExternalPeerPrincipal::from_scopes(
            TenantId::new(),
            Uuid::new_v4(),
            "grok-peer".into(),
            UserId::new(),
            &["boards:read".into(), "boards:comment".into()],
        )
        .unwrap();

        assert!(peer.can(Permission::BoardsRead));
        assert!(peer.can(Permission::BoardsComment));

        for forbidden in [
            Permission::PartsRead,
            Permission::PartsWrite,
            Permission::PartsRelease,
            Permission::BoardsWrite,
            Permission::OrdersRead,
            Permission::OrdersWrite,
            Permission::OrdersApprove,
            Permission::MailManage,
            Permission::BillingManage,
            Permission::VmUse,
            Permission::VmManage,
            Permission::LlmUse,
            Permission::AdminManage,
            Permission::AuditRead,
        ] {
            assert!(!peer.can(forbidden), "{forbidden:?} must be denied");
            assert!(matches!(peer.require(forbidden), Err(Error::Forbidden)));
        }

        let core_p = peer.to_core_principal();
        assert_eq!(core_p.role, Role::ExternalReviewer);
        assert_eq!(core_p.auth, AuthKind::DeviceToken);
        assert!(!core_p.can(Permission::PartsRead));
        assert!(!core_p.can(Permission::VmUse));
        assert!(!core_p.can(Permission::AdminManage));
    }

    #[test]
    fn validate_peer_scopes_rejects_elevated_or_unknown_scopes() {
        assert!(validate_peer_scopes(&["boards:read".into(), "boards:comment".into()]).is_ok());
        for bad in [
            "parts:read",
            "vm:use",
            "admin:manage",
            "orders:approve",
            "shell:exec",
            "*",
        ] {
            assert!(validate_peer_scopes(&[bad.into()]).is_err(), "{bad} must be rejected");
        }
    }
}
