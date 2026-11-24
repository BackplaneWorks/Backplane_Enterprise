//! Roles, permissions and the authenticated principal.

use crate::{Error, Result, TenantId, UserId};
use serde::{Deserialize, Serialize};

/// The five org roles of the spec (§3.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    OrgAdmin,
    Engineer,
    Librarian,
    Purchasing,
    ExternalReviewer,
}

impl Role {
    pub const ALL: [Role; 5] =
        [Role::OrgAdmin, Role::Engineer, Role::Librarian, Role::Purchasing, Role::ExternalReviewer];

    pub fn as_str(&self) -> &'static str {
        match self {
            Role::OrgAdmin => "org_admin",
            Role::Engineer => "engineer",
            Role::Librarian => "librarian",
            Role::Purchasing => "purchasing",
            Role::ExternalReviewer => "external_reviewer",
        }
    }

    pub fn parse(s: &str) -> Result<Role> {
        Role::ALL
            .into_iter()
            .find(|r| r.as_str() == s)
            .ok_or_else(|| Error::invalid("unknown role"))
    }

    /// What this role may do. The table is the single source of truth: no
    /// handler compares roles directly.
    pub fn permissions(&self) -> &'static [Permission] {
        use Permission::*;
        match self {
            Role::OrgAdmin => &Permission::ALL,
            Role::Engineer => &[
                PartsRead, PartsWrite, BoardsRead, BoardsComment, BoardsWrite, OrdersRead,
                OrdersWrite, VmUse, LlmUse,
            ],
            Role::Librarian => &[
                PartsRead, PartsWrite, PartsRelease, BoardsRead, BoardsComment, VmUse, LlmUse,
            ],
            Role::Purchasing => &[
                PartsRead, BoardsRead, BoardsComment, OrdersRead, OrdersWrite, OrdersApprove,
                MailManage,
            ],
            Role::ExternalReviewer => &[BoardsRead, BoardsComment],
        }
    }

    pub fn has(&self, p: Permission) -> bool {
        self.permissions().contains(&p)
    }
}

/// A capability checked by a handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Read the private part library (includes the KiCad HTTP library).
    PartsRead,
    /// Create and edit draft parts, symbols and footprints.
    PartsWrite,
    /// Move parts through review to Released / Obsolete.
    PartsRelease,
    BoardsRead,
    /// Pin review comments; the only write an external reviewer has.
    BoardsComment,
    /// Push revisions, manage ECOs.
    BoardsWrite,
    OrdersRead,
    /// Draft orders and request quotes.
    OrdersWrite,
    /// Approve purchase orders.
    OrdersApprove,
    /// Connect mailboxes, read the order mail ledger.
    MailManage,
    /// Stripe subscription, seats, invoices.
    BillingManage,
    /// Connect to one's own assigned Boat VM.
    VmUse,
    /// Create, assign, stop and delete Boat VMs.
    VmManage,
    /// Call LLM providers through the org policy.
    LlmUse,
    /// Users, roles, SSO, LLM policy, approval gates, key rotation.
    AdminManage,
    AuditRead,
}

impl Permission {
    pub const ALL: [Permission; 16] = [
        Permission::PartsRead,
        Permission::PartsWrite,
        Permission::PartsRelease,
        Permission::BoardsRead,
        Permission::BoardsComment,
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
    ];

    /// The scope string used in tokens, e.g. `parts:read`.
    pub fn scope(&self) -> &'static str {
        match self {
            Permission::PartsRead => "parts:read",
            Permission::PartsWrite => "parts:write",
            Permission::PartsRelease => "parts:release",
            Permission::BoardsRead => "boards:read",
            Permission::BoardsComment => "boards:comment",
            Permission::BoardsWrite => "boards:write",
            Permission::OrdersRead => "orders:read",
            Permission::OrdersWrite => "orders:write",
            Permission::OrdersApprove => "orders:approve",
            Permission::MailManage => "mail:manage",
            Permission::BillingManage => "billing:manage",
            Permission::VmUse => "vm:use",
            Permission::VmManage => "vm:manage",
            Permission::LlmUse => "llm:use",
            Permission::AdminManage => "admin:manage",
            Permission::AuditRead => "audit:read",
        }
    }

    pub fn from_scope(s: &str) -> Option<Permission> {
        Permission::ALL.into_iter().find(|p| p.scope() == s)
    }
}

/// How the caller proved who they are.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    /// Browser session cookie, issued after SSO. The only kind that counts as
    /// "a human at the keyboard" for approvals.
    Session,
    /// A user API token (desktop app, scripts, agents).
    UserToken,
    /// A narrow device token (e.g. KiCad's HTTP library config).
    DeviceToken,
}

impl AuthKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthKind::Session => "user",
            AuthKind::UserToken => "token",
            AuthKind::DeviceToken => "device",
        }
    }
}

/// Token scopes: everything the role allows, or an explicit subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scopes {
    All,
    Only(Vec<Permission>),
}

impl Scopes {
    pub fn parse(raw: &[String]) -> Scopes {
        if raw.iter().any(|s| s == "*") {
            return Scopes::All;
        }
        // Unknown scope strings grant nothing.
        Scopes::Only(raw.iter().filter_map(|s| Permission::from_scope(s)).collect())
    }

    pub fn to_strings(&self) -> Vec<String> {
        match self {
            Scopes::All => vec!["*".into()],
            Scopes::Only(ps) => ps.iter().map(|p| p.scope().to_string()).collect(),
        }
    }

    pub fn allows(&self, p: Permission) -> bool {
        match self {
            Scopes::All => true,
            Scopes::Only(ps) => ps.contains(&p),
        }
    }
}

/// The verified caller. Built only by [`crate::auth`]; the tenant in here is the
/// only tenant a request may touch.
#[derive(Clone)]
pub struct Principal {
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub role: Role,
    pub email: String,
    pub auth: AuthKind,
    pub scopes: Scopes,
    /// The `auth_tokens.id` of the credential used.
    pub token_id: uuid::Uuid,
}

// The e-mail address is personal data: keep it out of logs and spans.
impl std::fmt::Debug for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Principal")
            .field("tenant_id", &self.tenant_id)
            .field("user_id", &self.user_id)
            .field("role", &self.role)
            .field("auth", &self.auth)
            .finish_non_exhaustive()
    }
}

impl Principal {
    /// Role allows it AND the credential's scopes allow it.
    pub fn can(&self, p: Permission) -> bool {
        self.role.has(p) && self.scopes.allows(p)
    }

    pub fn require(&self, p: Permission) -> Result<()> {
        if self.can(p) {
            Ok(())
        } else {
            Err(Error::Forbidden)
        }
    }

    /// For actions that need a person, not an agent holding a token.
    pub fn require_interactive(&self) -> Result<()> {
        if self.auth == AuthKind::Session {
            Ok(())
        } else {
            Err(Error::Forbidden)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(role: Role, scopes: Scopes) -> Principal {
        Principal {
            tenant_id: TenantId::new(),
            user_id: UserId::new(),
            role,
            email: "a@example.com".into(),
            auth: AuthKind::UserToken,
            scopes,
            token_id: uuid::Uuid::new_v4(),
        }
    }

    #[test]
    fn role_strings_round_trip() {
        for r in Role::ALL {
            assert_eq!(Role::parse(r.as_str()).unwrap(), r);
        }
        assert!(Role::parse("root").is_err());
    }

    #[test]
    fn scope_strings_round_trip_and_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for p in Permission::ALL {
            assert_eq!(Permission::from_scope(p.scope()), Some(p));
            assert!(seen.insert(p.scope()));
        }
    }

    #[test]
    fn external_reviewer_can_only_read_and_comment_on_boards() {
        let allowed: Vec<_> =
            Permission::ALL.into_iter().filter(|p| Role::ExternalReviewer.has(*p)).collect();
        assert_eq!(allowed, vec![Permission::BoardsRead, Permission::BoardsComment]);
    }

    #[test]
    fn only_admin_holds_admin_permissions() {
        for r in Role::ALL {
            let admin = r == Role::OrgAdmin;
            for p in [
                Permission::AdminManage,
                Permission::AuditRead,
                Permission::BillingManage,
                Permission::VmManage,
            ] {
                assert_eq!(r.has(p), admin, "{r:?} {p:?}");
            }
        }
        assert!(!Role::Engineer.has(Permission::OrdersApprove));
        assert!(!Role::Engineer.has(Permission::PartsRelease));
        assert!(!Role::Purchasing.has(Permission::PartsWrite));
    }

    #[test]
    fn scopes_narrow_but_never_widen() {
        let p = principal(Role::Engineer, Scopes::Only(vec![Permission::PartsRead]));
        assert!(p.can(Permission::PartsRead));
        assert!(!p.can(Permission::PartsWrite));
        // A scope the role lacks grants nothing.
        let p = principal(Role::ExternalReviewer, Scopes::Only(vec![Permission::AdminManage]));
        assert!(!p.can(Permission::AdminManage));
        // Unknown scope strings are dropped.
        assert_eq!(Scopes::parse(&["nope".into()]), Scopes::Only(vec![]));
        assert_eq!(Scopes::parse(&["*".into()]), Scopes::All);
    }

    #[test]
    fn debug_hides_email() {
        let p = principal(Role::Engineer, Scopes::All);
        assert!(!format!("{p:?}").contains("example.com"));
    }
}
