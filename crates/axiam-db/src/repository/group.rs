//! SurrealDB implementation of [`GroupRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::group::{CreateGroup, Group, UpdateGroup};
use axiam_core::models::user::{User, UserStatus};
use axiam_core::repository::{GroupRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

/// DB-side row struct for queries where the UUID is already known.
#[derive(Debug, SurrealValue)]
struct GroupRow {
    tenant_id: String,
    name: String,
    description: String,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// DB-side row struct that includes the record ID via `meta::id(id)`.
#[derive(Debug, SurrealValue)]
struct GroupRowWithId {
    record_id: String,
    tenant_id: String,
    name: String,
    description: String,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl GroupRowWithId {
    fn try_into_group(self) -> Result<Group, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        Ok(Group {
            id,
            tenant_id,
            name: self.name,
            description: self.description,
            metadata: self.metadata,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// DB-side row struct for user members returned from edge queries.
#[derive(Debug, SurrealValue)]
struct MemberRow {
    record_id: String,
    tenant_id: String,
    username: String,
    email: String,
    password_hash: String,
    status: String,
    mfa_enabled: bool,
    mfa_secret: Option<String>,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

fn parse_status(s: &str) -> Result<UserStatus, DbError> {
    match s {
        "Active" => Ok(UserStatus::Active),
        "Inactive" => Ok(UserStatus::Inactive),
        "Locked" => Ok(UserStatus::Locked),
        "PendingVerification" => Ok(UserStatus::PendingVerification),
        other => Err(DbError::Migration(format!("unknown user status: {other}"))),
    }
}

impl MemberRow {
    fn try_into_user(self) -> Result<User, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        Ok(User {
            id,
            tenant_id,
            username: self.username,
            email: self.email,
            password_hash: self.password_hash,
            status: parse_status(&self.status)?,
            mfa_enabled: self.mfa_enabled,
            mfa_secret: self.mfa_secret,
            metadata: self.metadata,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Row struct for count queries.
#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

/// SurrealDB implementation of the Group repository.
#[derive(Clone)]
pub struct SurrealGroupRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealGroupRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> GroupRepository for SurrealGroupRepository<C> {
    async fn create(&self, input: CreateGroup) -> AxiamResult<Group> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        let tenant_id_str = input.tenant_id.to_string();

        let metadata = input
            .metadata
            .unwrap_or(serde_json::Value::Object(Default::default()));

        let result = self
            .db
            .query(
                "CREATE type::record('group', $id) SET \
                 tenant_id = $tenant_id, \
                 name = $name, description = $description, \
                 metadata = $metadata",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str.clone()))
            .bind(("name", input.name))
            .bind(("description", input.description))
            .bind(("metadata", metadata))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<GroupRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "group".into(),
            id: id_str,
        })?;

        let tenant_id = Uuid::parse_str(&tenant_id_str)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(Group {
            id,
            tenant_id,
            name: row.name,
            description: row.description,
            metadata: row.metadata,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Group> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let mut result = self
            .db
            .query(
                "SELECT * FROM type::record('group', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<GroupRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "group".into(),
            id: id_str,
        })?;

        let tenant_id_parsed = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(Group {
            id,
            tenant_id: tenant_id_parsed,
            name: row.name,
            description: row.description,
            metadata: row.metadata,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn update(&self, tenant_id: Uuid, id: Uuid, input: UpdateGroup) -> AxiamResult<Group> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let mut sets = Vec::new();
        if input.name.is_some() {
            sets.push("name = $name");
        }
        if input.description.is_some() {
            sets.push("description = $description");
        }
        if input.metadata.is_some() {
            sets.push("metadata = $metadata");
        }
        sets.push("updated_at = time::now()");

        let query = format!(
            "UPDATE type::record('group', $id) SET {} \
             WHERE tenant_id = $tenant_id",
            sets.join(", ")
        );

        let mut builder = self
            .db
            .query(&query)
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str));

        if let Some(name) = input.name {
            builder = builder.bind(("name", name));
        }
        if let Some(description) = input.description {
            builder = builder.bind(("description", description));
        }
        if let Some(metadata) = input.metadata {
            builder = builder.bind(("metadata", metadata));
        }

        let result = builder.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<GroupRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "group".into(),
            id: id_str,
        })?;

        let tenant_id_parsed = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(Group {
            id,
            tenant_id: tenant_id_parsed,
            name: row.name,
            description: row.description,
            metadata: row.metadata,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        // Delete associated membership edges first, then the group record.
        let query = format!(
            "DELETE member_of WHERE out = group:`{id_str}`; \
             DELETE type::record('group', $id) WHERE tenant_id = $tenant_id;"
        );

        self.db
            .query(query)
            .bind(("id", id_str))
            .bind(("tenant_id", tenant_id_str))
            .await
            .map_err(DbError::from)?;

        Ok(())
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<Group>> {
        let tenant_id_str = tenant_id.to_string();

        let mut count_result = self
            .db
            .query(
                "SELECT count() AS total FROM group \
                 WHERE tenant_id = $tenant_id GROUP ALL",
            )
            .bind(("tenant_id", tenant_id_str.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM group \
                 WHERE tenant_id = $tenant_id \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<GroupRowWithId> = result.take(0).map_err(DbError::from)?;

        let items = rows
            .into_iter()
            .map(|row| row.try_into_group())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(PaginatedResult {
            items,
            total,
            offset: pagination.offset,
            limit: pagination.limit,
        })
    }

    async fn add_member(&self, tenant_id: Uuid, user_id: Uuid, group_id: Uuid) -> AxiamResult<()> {
        let user_id_str = user_id.to_string();
        let group_id_str = group_id.to_string();
        let tenant_id_str = tenant_id.to_string();

        // Verify both user and group belong to the same tenant.
        let mut check = self
            .db
            .query(
                "SELECT count() AS total FROM user \
                 WHERE id = type::record('user', $user_id) \
                 AND tenant_id = $tenant_id GROUP ALL; \
                 SELECT count() AS total FROM group \
                 WHERE id = type::record('group', $group_id) \
                 AND tenant_id = $tenant_id GROUP ALL;",
            )
            .bind(("user_id", user_id_str.clone()))
            .bind(("group_id", group_id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .await
            .map_err(DbError::from)?;

        let user_count: Vec<CountRow> = check.take(0).map_err(DbError::from)?;
        if user_count.first().map(|r| r.total).unwrap_or(0) == 0 {
            return Err(DbError::NotFound {
                entity: "user".into(),
                id: user_id_str,
            }
            .into());
        }

        let group_count: Vec<CountRow> = check.take(1).map_err(DbError::from)?;
        if group_count.first().map(|r| r.total).unwrap_or(0) == 0 {
            return Err(DbError::NotFound {
                entity: "group".into(),
                id: group_id_str,
            }
            .into());
        }

        // Create the membership edge (IF NOT EXISTS avoids duplicates).
        let query = format!("RELATE user:`{user_id_str}` -> member_of -> group:`{group_id_str}`;");

        self.db.query(query).await.map_err(DbError::from)?;

        Ok(())
    }

    async fn remove_member(
        &self,
        _tenant_id: Uuid,
        user_id: Uuid,
        group_id: Uuid,
    ) -> AxiamResult<()> {
        let user_id_str = user_id.to_string();
        let group_id_str = group_id.to_string();

        self.db
            .query(
                "DELETE member_of WHERE \
                 in = type::record('user', $user_id) AND \
                 out = type::record('group', $group_id)",
            )
            .bind(("user_id", user_id_str))
            .bind(("group_id", group_id_str))
            .await
            .map_err(DbError::from)?;

        Ok(())
    }

    async fn get_members(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<User>> {
        let tenant_id_str = tenant_id.to_string();
        let group_id_str = group_id.to_string();

        // Count total members.
        let mut count_result = self
            .db
            .query(
                "SELECT count() AS total FROM member_of \
                 WHERE out = type::record('group', $group_id) GROUP ALL",
            )
            .bind(("group_id", group_id_str.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        // Fetch member users via the edge.
        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM user \
                 WHERE tenant_id = $tenant_id \
                 AND id IN (\
                     SELECT VALUE in FROM member_of \
                     WHERE out = type::record('group', $group_id)\
                 ) \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("group_id", group_id_str))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<MemberRow> = result.take(0).map_err(DbError::from)?;

        let items = rows
            .into_iter()
            .map(|row| row.try_into_user())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(PaginatedResult {
            items,
            total,
            offset: pagination.offset,
            limit: pagination.limit,
        })
    }

    async fn get_user_groups(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<Vec<Group>> {
        let tenant_id_str = tenant_id.to_string();
        let user_id_str = user_id.to_string();

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM group \
                 WHERE tenant_id = $tenant_id \
                 AND id IN (\
                     SELECT VALUE out FROM member_of \
                     WHERE in = type::record('user', $user_id)\
                 )",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("user_id", user_id_str))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<GroupRowWithId> = result.take(0).map_err(DbError::from)?;

        let groups = rows
            .into_iter()
            .map(|row| row.try_into_group())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(groups)
    }
}
