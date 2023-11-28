use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use lazy_static::lazy_static;
use rusqlite::{OptionalExtension, params};
use rusqlite_migration::{AsyncMigrations, M};
use tabby_common::path::tabby_root;
use tokio_rusqlite::Connection;

lazy_static! {
    static ref MIGRATIONS: AsyncMigrations = AsyncMigrations::new(vec![
        M::up(r#"
            CREATE TABLE IF NOT EXISTS registration_token (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT (DATETIME('now')),
                updated_at TIMESTAMP DEFAULT (DATETIME('now')),
                CONSTRAINT `idx_token` UNIQUE (`token`)
            );
        "#),
        M::up(r#"
            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     VARCHAR(150) NOT NULL COLLATE NOCASE,
                email        VARCHAR(150) NOT NULL COLLATE NOCASE,
                password     VARCHAR(128) NOT NULL,
                is_superuser BOOLEAN NOT NULL DEFAULT 0,
                is_active    BOOLEAN NOT NULL DEFAULT 1,
                created_at   TIMESTAMP DEFAULT (DATETIME('now')),
                updated_at   TIMESTAMP DEFAULT (DATETIME('now')),
                CONSTRAINT `idx_username` UNIQUE (`username`),
                CONSTRAINT `idx_email` UNIQUE (`email`)
            );
        "#),
        M::up(r#"
            CREATE TABLE IF NOT EXISTS roles (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        VARCHAR(150) NOT NULL COLLATE NOCASE,
                description VARCHAR(255) NOT NULL,
                created_at  TIMESTAMP DEFAULT (DATETIME('now')),
                updated_at  TIMESTAMP DEFAULT (DATETIME('now')),
                CONSTRAINT `idx_name` UNIQUE (`name`)
            );
        "#),
        M::up(r#"
            CREATE TABLE IF NOT EXISTS user_role_bindings (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id  INTEGER NOT NULL,
                role_id  INTEGER NOT NULL,
                created_at  TIMESTAMP DEFAULT (DATETIME('now')),
                CONSTRAINT `idx_user_role` UNIQUE (`user_id`, `role_id`)
            );
        "#),
        M::up(r#"
            CREATE TABLE IF NOT EXISTS permissions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        VARCHAR(150) NOT NULL COLLATE NOCASE,
                description VARCHAR(255) NOT NULL,
                created_at  TIMESTAMP DEFAULT (DATETIME('now')),
                updated_at  TIMESTAMP DEFAULT (DATETIME('now')),
                CONSTRAINT `idx_name` UNIQUE (`name`)
            );
        "#),
        M::up(r#"
            CREATE TABLE IF NOT EXISTS role_permission_bindings (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                role_id  INTEGER NOT NULL,
                permission_id  INTEGER NOT NULL,
                created_at  TIMESTAMP DEFAULT (DATETIME('now')),
                CONSTRAINT `idx_role_permission` UNIQUE (`role_id`, `permission_id`)
            );
        "#),
    ]);
}

#[derive(Debug, Default)]
pub struct User {
    is_active: bool,
    created_at: String,
    updated_at: String,

    pub id: u32,
    pub username: String,
    pub email: String,
    pub password: String,
    pub is_superuser: bool,
}

async fn db_path() -> Result<PathBuf> {
    let db_dir = tabby_root().join("ee");
    tokio::fs::create_dir_all(db_dir.clone()).await?;
    Ok(db_dir.join("db.sqlite"))
}

pub struct DbConn {
    conn: Arc<Connection>,
}

impl DbConn {
    pub async fn new() -> Result<Self> {
        let db_path = db_path().await?;
        let conn = Connection::open(db_path).await?;
        Self::init_db(conn).await
    }

    /// Initialize database, create tables and insert first token if not exist
    /// Add default `admin` if not exist
    async fn init_db(mut conn: Connection) -> Result<Self> {
        MIGRATIONS.to_latest(&mut conn).await?;

        let token = uuid::Uuid::new_v4().to_string();
        conn.call(move |c| {
            c.execute(
                r#"INSERT OR IGNORE INTO registration_token (id, token) VALUES (1, ?)"#,
                params![token],
            )
        })
        .await?;

        conn.call(|c| {
            c.execute_batch(r#"
                BEGIN;
                INSERT OR IGNORE INTO users (username, email, password, is_superuser) VALUES ('tabby', 'hello@tabby.com', '$argon2id$v=19$m=19456,t=2,p=1$1JuxpDPavKcYpDzo95rnMw$Wep8E2BRzIHZWQNCx+Gr/VKdiE68ngBUmq7vy/8CDhc', 1);
                INSERT OR IGNORE INTO roles (name, description) VALUES ('admin', 'System default administrator');
                INSERT OR IGNORE INTO user_role_bindings (user_id, role_id) VALUES (
                    (SELECT id FROM users WHERE username = 'tabby'),
                    (SELECT id FROM roles WHERE name = 'admin')
                );
                INSERT OR IGNORE INTO permissions (name, description) VALUES ('repo.resolve.view', 'Access to local repositories');
                INSERT OR IGNORE INTO permissions (name, description) VALUES ('repo.meta.view', 'Access to local repositories meta');
                INSERT OR IGNORE INTO role_permission_bindings (role_id, permission_id) VALUES (
                    (SELECT id FROM roles WHERE name = 'admin'),
                    (SELECT id FROM permissions WHERE name = 'repo.resolve.view')
                );
                INSERT OR IGNORE INTO role_permission_bindings (role_id, permission_id) VALUES (
                    (SELECT id FROM roles WHERE name = 'admin'),
                    (SELECT id FROM permissions WHERE name = 'repo.meta.view')
                );
                COMMIT;
            "#)
        })
        .await?;

        Ok(Self {
            conn: Arc::new(conn),
        })
    }
}

/// db read/write operations for `registration_token` table
impl DbConn {

    /// Query token from database.
    /// Since token is global unique for each tabby server, by right there's only one row in the table.
    pub async fn read_registration_token(&self) -> Result<String> {
        let token = self
            .conn
            .call(|conn| {
                conn.query_row(
                    r#"SELECT token FROM registration_token WHERE id = 1"#,
                    [],
                    |row| row.get(0),
                )
            })
            .await?;

        Ok(token)
    }

    /// Update token in database.
    pub async fn reset_registration_token(&self) -> Result<String> {
        let token = uuid::Uuid::new_v4().to_string();
        let result = token.clone();
        let updated_at = chrono::Utc::now().timestamp() as u32;

        let res = self
            .conn
            .call(move |conn| {
                conn.execute(
                    r#"UPDATE registration_token SET token = ?, updated_at = ? WHERE id = 1"#,
                    params![token, updated_at],
                )
            })
            .await?;
        if res != 1 {
            return Err(anyhow::anyhow!("failed to update token"));
        }

        Ok(result)
    }
}

/// db read/write operations for `users` table
impl DbConn {

    pub async fn create_user(&self, username: String, email: String, password: String, is_superuser: bool) -> Result<()> {
        let res = self
            .conn
            .call(move |c| {
                c.execute(
                    r#"INSERT INTO users (username, email, password, is_superuser) VALUES (?, ?, ?, ?)"#,
                    params![username, email, password, is_superuser],
                )
            })
            .await?;
        if res != 1 {
            return Err(anyhow::anyhow!("failed to create user"));
        }

        Ok(())
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let username = username.to_string();
        let user = self
            .conn
            .call(move |c| {
                c.query_row(
                    r#"SELECT id, username, email, password, is_superuser, is_active, created_at, updated_at FROM users WHERE username = ?"#,
                    params![username],
                    |row| {
                        Ok(User {
                            id: row.get(0)?,
                            username: row.get(1)?,
                            email: row.get(2)?,
                            password: row.get(3)?,
                            is_superuser: row.get(4)?,
                            is_active: row.get(5)?,
                            created_at: row.get(6)?,
                            updated_at: row.get(7)?,
                        })
                    },
                ).optional()
            })
            .await?;

        Ok(user)
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let email = email.to_string();
        let user = self
            .conn
            .call(move |c| {
                c.query_row(
                    r#"SELECT id, username, email, password, is_superuser, is_active, created_at, updated_at FROM users WHERE email = ?"#,
                    params![email],
                    |row| {
                        Ok(User {
                            id: row.get(0)?,
                            username: row.get(1)?,
                            email: row.get(2)?,
                            password: row.get(3)?,
                            is_superuser: row.get(4)?,
                            is_active: row.get(5)?,
                            created_at: row.get(6)?,
                            updated_at: row.get(7)?,
                        })
                    },
                ).optional()
            })
            .await?;

        Ok(user)
    }
}

/// db read operations to query permissions
impl DbConn {
    pub async fn get_user_all_permissions(&self, username: &str) -> Result<Vec<String>> {
        let username = username.to_string();

        let perms = self.conn.call(move |c| {
            let mut stmt = c.prepare(
                r#"SELECT p.name FROM permissions p
                    INNER JOIN role_permission_bindings rpb ON rpb.permission_id = p.id
                    INNER JOIN user_role_bindings urb ON urb.role_id = rpb.role_id
                    INNER JOIN users u ON u.id = urb.user_id
                    WHERE u.username = ?"#,
            )?;
            let rows = stmt
                .query_map(params![username], |row| Ok(row.get(0)?))?
                .collect::<Result<Vec<String>, rusqlite::Error>>()?;
            Ok(rows)
        }).await?;

        Ok(perms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn new_in_memory() -> Result<DbConn> {
        let conn = Connection::open_in_memory().await?;
        DbConn::init_db(conn).await
    }

    #[tokio::test]
    async fn migrations_test() {
        assert!(MIGRATIONS.validate().await.is_ok());
    }

    #[tokio::test]
    async fn test_token() {
        let conn = new_in_memory().await.unwrap();
        let token = conn.read_registration_token().await.unwrap();
        assert_eq!(token.len(), 36);
    }

    #[tokio::test]
    async fn test_update_token() {
        let conn = new_in_memory().await.unwrap();

        let old_token = conn.read_registration_token().await.unwrap();
        conn.reset_registration_token().await.unwrap();
        let new_token = conn.read_registration_token().await.unwrap();
        assert_eq!(new_token.len(), 36);
        assert_ne!(old_token, new_token);
    }

    #[tokio::test]
    async fn test_create_user() {
        let conn = new_in_memory().await.unwrap();

        let username = "test";
        let email = "test@example.com";
        let passwd = "123456";
        let is_superuser = true;
        conn.create_user(
            username.to_string(),
            email.to_string(),
            passwd.to_string(),
            is_superuser
        ).await.unwrap();

        let user1 = conn.get_user_by_username(username).await.unwrap().unwrap();
        let user2 = conn.get_user_by_email(&email).await.unwrap().unwrap();
        assert_eq!(user1.id, user2.id);
    }

    #[tokio::test]
    async fn test_get_user_by_username() {
        let conn = new_in_memory().await.unwrap();

        let username = "admin";
        let user = conn.get_user_by_username(username).await.unwrap();

        assert!(user.is_none());
    }

    #[tokio::test]
    async fn test_get_user_by_email() {
        let conn = new_in_memory().await.unwrap();

        let email = "hello@example.com";
        let user = conn.get_user_by_email(email).await.unwrap();

        assert!(user.is_none());
    }
}
