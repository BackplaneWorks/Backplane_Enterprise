//! Typed identifiers, so a user id can never be passed where a tenant id is expected.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }
        impl From<Uuid> for $name {
            fn from(u: Uuid) -> Self {
                Self(u)
            }
        }
        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }
    };
}

id!(
    /// A customer organisation. The unit of isolation for rows, keys and objects.
    TenantId
);
id!(
    /// A user inside one tenant.
    UserId
);

impl TenantId {
    /// The object-store prefix every artifact of this tenant lives under.
    /// Build keys only through this, never by formatting a tenant id by hand.
    pub fn s3_prefix(&self) -> String {
        format!("tenants/{}/", self.0)
    }

    /// An object key under this tenant's prefix. `rel` may not escape it.
    pub fn s3_key(&self, rel: &str) -> crate::Result<String> {
        let bad = rel.is_empty()
            || rel.starts_with('/')
            || rel.contains('\\')
            || rel.contains('\0')
            || rel.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..");
        if bad {
            return Err(crate::Error::invalid("invalid object path"));
        }
        Ok(format!("{}{}", self.s3_prefix(), rel))
    }
}
