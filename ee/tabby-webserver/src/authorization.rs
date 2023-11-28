//! Simple RBAC authorization service
//!
//! By saying `simple`, there are some assumptions and limitations:
//!
//! - permissions are just plain dot-separated, lower-case text string such as `repo.view`, `repo.delete`
//!   - permissions are case insensitive, so `read` is the same as `READ`.
//!   - permissions themselves combine the target resource and the expected operation, such as `repo.view`
//!   - permissions have no hierarchy support, such as `repo.dir.view` is not a child of `repo.dir`, nor `repo`
//!   - permissions have no wildcards support, such as `repo.*`, `repo.write.*`.
//!   - permissions have no grouping support. For example, `repo.view` and `repo.delete` are not grouped
//!     into one `repo_ops` group.
//!
//! - users are not granted permissions directly, but through roles
//!   - users can have multiple roles
//!
//! - roles are group of users
//!   - roles have no inheritance support. For example, user in `admin` role does not
//!     inherit permissions from `developer` role if he/she is not a `developer` role member.
//!   - roles can have multiple permissions
//!
//! Above limitations can be addressed by extending current implementation or replacing it with existing
//! authorization library such as [oso](https://github.com/osohq/oso), [casbin](https://github.com/casbin/casbin), etc.
//!
use std::collections::HashSet;

use anyhow::Result;
use async_trait::async_trait;
use lazy_static::lazy_static;
use regex::Regex;
use tracing::{debug, error};
use validator::Validate;

use crate::{authentication::UserInfo, server::ServerContext};

lazy_static! {
    static ref PERMISSION_RE: Regex = Regex::new(r"^(\*|[a-z\.]+)$").unwrap();
}

#[derive(Hash, Eq, PartialEq, Validate)]
pub struct Permission {
    #[validate(regex = "PERMISSION_RE")]
    name: String,
}

impl Permission {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_ascii_lowercase(),
        }
    }
}

impl From<&String> for Permission {
    fn from(name: &String) -> Self {
        Self::new(name)
    }
}

/// Authorization service
/// Inspired by https://github.com/maxcountryman/axum-login/blob/main/axum-login/src/backend.rs
#[async_trait]
pub trait AuthorizationService {
    type User: Sync;

    async fn get_user_permissions(&self, _user: &Self::User) -> Result<HashSet<Permission>> {
        Ok(HashSet::new())
    }

    async fn get_role_permissions(&self, _user: &Self::User) -> Result<HashSet<Permission>> {
        Ok(HashSet::new())
    }

    async fn get_all_permissions(&self, user: &Self::User) -> Result<HashSet<Permission>> {
        let mut perms = HashSet::new();
        perms.extend(self.get_user_permissions(user).await?);
        perms.extend(self.get_role_permissions(user).await?);
        Ok(perms)
    }

    async fn has_permission(&self, user: &Self::User, perm: &Permission) -> Result<bool> {
        Ok(self.get_all_permissions(user).await?.contains(perm))
    }

    async fn has_all_permissions(&self, user: &Self::User, perms: &[Permission]) -> Result<bool> {
        let all_perms = self.get_all_permissions(user).await?;
        Ok(perms.iter().all(|p| all_perms.contains(p)))
    }
}

#[async_trait]
impl AuthorizationService for ServerContext {
    type User = UserInfo;

    async fn get_role_permissions(&self, user: &Self::User) -> Result<HashSet<Permission>> {
        let perms = match self.db_conn.get_user_all_permissions(user.username()).await {
            Ok(perms) => perms,
            Err(err) => {
                error!("failed to fetch permission for user {:?} - {:?}", user, err);
                vec![]
            }
        };
        debug!("raw perms = {:?}", perms);
        let perms = perms.into_iter().map(|p| Permission::new(&p)).collect();
        Ok(perms)
    }
}
