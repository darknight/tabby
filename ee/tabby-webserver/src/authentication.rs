use std::borrow::Cow;
use std::env;
use juniper::{GraphQLInputObject, GraphQLObject};
use async_trait::async_trait;
use anyhow::Result;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use crate::server::ServerContext;
use validator::{Validate, ValidationError};
use jsonwebtoken as jwt;

lazy_static! {
    static ref USERNAME_RE: Regex = Regex::new(r"^[a-zA-Z0-9_]+$").unwrap();
    static ref JWT_ENCODING_KEY = jwt::EncodingKey::from_secret(
        env::var("JWT_ACCESS_TOKEN_SECRET").unwrap_or("default_secret".to_string()).as_bytes()
    );
    static ref JWT_DEFAULT_EXP: u64 = 30 * 24 * 60 * 60; // 30 days
}

#[derive(Debug, GraphQLObject)]
pub struct AuthError {
    message: String,
    code: String,
}

impl From<ValidationError> for AuthError {
    fn from(err: ValidationError) -> Self {
        Self {
            message: err.message.unwrap_or(Cow::from("unknown error")).into(),
            code: err.code.to_string(),
        }
    }
}

impl From<argon2::Error> for AuthError {
    fn from(err: argon2::Error) -> Self {
        Self {
            message: err.to_string(),
            code: "password_hash_error".to_string(),
        }
    }
}

impl From<jwt::errors::Error> for AuthError {
    fn from(err: jwt::errors::Error) -> Self {
        Self {
            message: err.to_string(),
            code: "jwt_error".to_string(),
        }
    }
}

#[derive(Validate, GraphQLInputObject)]
pub struct RegisterInput {
    #[validate(regex = "USERNAME_RE")]
    #[validate(length(min = 8, "username_too_short", message = "Username must be at least 8 characters"))]
    #[validate(length(max = 20, "username_too_long", message = "Username must be at most 20 characters"))]
    pub username: String,
    #[validate(email)]
    #[validate(length(max = 128, code = "email_too_long", message = "Email must be at most 128 characters"))]
    pub email: String,
    #[validate(length(min = 8, code = "password_too_short", message = "Password must be at least 8 characters"))]
    #[validate(length(max = 20, code = "password_too_long", message = "Password must be at most 20 characters"))]
    #[validate(must_match(other = "password2", code = "password_mismatch", message = "Passwords do not match"))]
    pub password1: String,
    #[validate(length(min = 8, max = 20))]
    pub password2: String,
}

impl std::fmt::Debug for RegisterInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterInput")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password1", &"********")
            .field("password2", &"********")
            .finish()
    }
}

#[derive(Debug, GraphQLObject)]
pub struct RegisterResponse {
    access_token: String,
    refresh_token: String,
    errors: Vec<AuthError>,
}

impl RegisterResponse {
    pub fn new(access_token: String, refresh_token: String) -> Self {
        Self {
            access_token,
            refresh_token,
            errors: vec![],
        }
    }

    fn with_error(error: AuthError) -> Self {
        Self {
            access_token: "".to_string(),
            refresh_token: "".to_string(),
            errors: vec![error],
        }
    }

    fn with_errors(errors: Vec<AuthError>) -> Self {
        Self {
            access_token: "".to_string(),
            refresh_token: "".to_string(),
            errors,
        }
    }
}

#[derive(GraphQLInputObject)]
pub struct LoginInput {
    #[validate(length(min = 8, "username_too_short", message = "Username must be at least 8 characters"))]
    #[validate(length(max = 20, "username_too_long", message = "Username must be at most 20 characters"))]
    pub username: Option<String>,
    #[validate(email)]
    #[validate(length(max = 128, code = "email_too_long", message = "Email must be at most 128 characters"))]
    pub email: Option<String>,
    #[validate(length(min = 8, code = "password_too_short", message = "Password must be at least 8 characters"))]
    #[validate(length(max = 20, code = "password_too_long", message = "Password must be at most 20 characters"))]
    pub password: String,
}

impl std::fmt::Debug for LoginInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginInput")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &"********")
            .finish()
    }
}

#[derive(Debug, GraphQLObject)]
pub struct LoginResponse {
    access_token: String,
    refresh_token: String,
    errors: Vec<AuthError>,
    user: UserResponse,
}

impl LoginResponse {

    fn new(access_token: String, refresh_token: String, user: UserResponse) -> Self {
        Self {
            access_token,
            refresh_token,
            errors: vec![],
            user,
        }
    }

    fn with_error(error: AuthError) -> Self {
        Self {
            access_token: "".to_string(),
            refresh_token: "".to_string(),
            errors: vec![error],
            user: UserResponse::default(),
        }
    }

    fn with_errors(errors: Vec<AuthError>) -> Self {
        Self {
            access_token: "".to_string(),
            refresh_token: "".to_string(),
            errors,
            user: UserResponse::default(),
        }
    }
}

#[derive(Debug, Default, GraphQLObject)]
pub struct UserResponse {
    id: u32,
    username: String,
}

impl UserResponse {
    fn new(id: u32, username: String) -> Self {
        Self {
            id,
            username,
        }
    }
}

#[derive(Debug, GraphQLObject)]
pub struct RefreshTokenResponse {
    access_token: String,
    refresh_token: String,
    refresh_expires_in: u32,
    errors: Vec<AuthError>,
}

#[derive(Debug, GraphQLObject)]
pub struct VerifyAccessTokenResponse {
    errors: Vec<AuthError>,
    claims: Claims,
}

impl VerifyAccessTokenResponse {
    fn new(claims: Claims) -> Self {
        Self {
            errors: vec![],
            claims,
        }
    }

    fn with_error(error: AuthError) -> Self {
        Self {
            errors: vec![error],
            claims: Claims::default(),
        }
    }

    fn with_errors(errors: Vec<AuthError>) -> Self {
        Self {
            errors,
            claims: Claims::default(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UserInfo {
    username: String,
    is_superuser: bool,
}

impl UserInfo {
    pub fn new(username: String, is_superuser: bool) -> Self {
        Self {
            username,
            is_superuser,
        }
    }

    pub fn is_superuser(&self) -> bool {
        self.is_superuser
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Claims {
    // Required. Expiration time (as UTC timestamp)
    exp: u64,
    // Optional. Issued at (as UTC timestamp)
    iat: u64,
    // Customized. user info
    user: UserInfo,
}

impl Claims {
    fn new(user: UserInfo) -> Self {
        let now = jwt::get_current_timestamp();
        Self {
            iat: now,
            exp: now + JWT_DEFAULT_EXP,
            user,
        }
    }

    pub fn user_info(self) -> UserInfo {
        self.user
    }
}

#[async_trait]
pub trait AuthenticationService {
    async fn register(&self, input: RegisterInput) -> Result<RegisterResponse>;
    async fn login(&self, input: LoginInput) -> Result<LoginResponse>;
    async fn refresh_token(&self, refresh_token: String) -> Result<RefreshTokenResponse>;
    async fn verify_access_token(&self, access_token: String) -> Result<VerifyAccessTokenResponse>;
}

impl AuthenticationService for ServerContext {
    async fn register(&self, input: RegisterInput) -> Result<RegisterResponse> {
        if let Err(err) = input.validate() {
            let mut errors = vec![];
            for (_, err) in err.field_errors() {
                errors.push(err.into());
            }
            let resp = RegisterResponse::with_errors(errors);
            return Ok(resp);
        }

        // check if username exists
        if let Some(_) = self.db_conn.get_user_by_email(&input.email).await? {
            let resp = RegisterResponse::with_error(
                AuthError {
                    message: "Email already exists".to_string(),
                    code: "email_already_exists".to_string(),
                }
            );
            return Ok(resp);
        }
        // check if email exists
        if let Some(_) = self.db_conn.get_user_by_username(&input.username).await? {
            let resp = RegisterResponse::with_error(
                AuthError {
                    message: "Username already exists".to_string(),
                    code: "username_already_exists".to_string(),
                }
            );
            return Ok(resp);
        }

        let pwd_hash = match password_hash(&input.password1) {
            Ok(hash) => hash,
            Err(err) => {
                return Ok(RegisterResponse::with_error(err.into()));
            }
        };

        self.db_conn.create_user(input.username.clone(), input.email.clone(),
                                 pwd_hash, false).await?;
        let user = self.db_conn.get_user_by_username(&input.username).await?.unwrap();

        let access_token = match generate_jwt(
            Claims::new(UserInfo::new(user.username.clone(), user.is_superuser))) {
            Ok(token) => token,
            Err(err) => {
                return Ok(RegisterResponse::with_error(err.into()));
            }
        };

        // FIXME: generate refresh token

        let resp = RegisterResponse::new(access_token, "".to_string());
        Ok(resp)
    }

    async fn login(&self, input: LoginInput) -> Result<LoginResponse> {
        if input.email.is_none() && input.username.is_none() {
            let resp = LoginResponse::with_error(
                AuthError {
                    message: "Username or email is required".to_string(),
                    code: "username_or_email_required".to_string(),
                }
            );
            return Ok(resp);
        }
        if let Err(err) = input.validate() {
            let mut errors = vec![];
            for (_, err) in err.field_errors() {
                errors.push(err.into());
            }
            let resp = LoginResponse::with_errors(errors);
            return Ok(resp);
        }

        let user = if let Some(email) = input.email {
            self.db_conn.get_user_by_email(&email).await?
        } else {
            self.db_conn.get_user_by_username(&input.username.unwrap()).await?
        };

        let user = match user {
            Some(user) => user,
            None => {
                let resp = LoginResponse::with_error(
                    AuthError {
                        message: "User not found".to_string(),
                        code: "user_not_found".to_string(),
                    }
                );
                return Ok(resp);
            }
        };

        if !password_verify(&input.password, &user.password) {
            let resp = LoginResponse::with_error(
                AuthError {
                    message: "Incorrect password".to_string(),
                    code: "incorrect_password".to_string(),
                }
            );
            return Ok(resp);
        }

        let access_token = match generate_jwt(
            Claims::new(UserInfo::new(user.username.clone(), user.is_superuser))) {
            Ok(token) => token,
            Err(err) => {
                return Ok(LoginResponse::with_error(err.into()));
            }
        };

        // FIXME: generate refresh token

        let resp = LoginResponse::new(
            access_token,
            "".to_string(),
            UserResponse::new(user.id, user.username),
        );
        Ok(resp)
    }

    // FIXME: implement refresh token
    async fn refresh_token(&self, refresh_token: String) -> Result<RefreshTokenResponse> {
        unimplemented!()
    }

    async fn verify_access_token(&self, access_token: String) -> Result<VerifyAccessTokenResponse> {
        let claims = match validate_jwt(&access_token) {
            Ok(claims) => claims,
            Err(err) => {
                return Ok(VerifyAccessTokenResponse::with_error(err.into()));
            }
        };

        let resp = VerifyAccessTokenResponse::new(claims);
        Ok(resp)
    }
}

fn password_hash(raw: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(raw.as_bytes(), salt.as_ref())?
        .to_string();

    Ok(hash)
}

fn password_verify(raw: &str, hash: &str) -> bool {
    if let Ok(parsed_hash) = argon2::PasswordHash::new(hash) {
        let argon2 = Argon2::default();
        argon2.verify_password(raw.as_bytes(), &parsed_hash).is_ok()
    } else {
        false
    }
}

fn generate_jwt(claims: Claims) -> Result<String> {
    let header = jwt::Header::default();
    let token = jwt::encode(&header, &claims, &JWT_ENCODING_KEY)?;
    Ok(token)
}

pub fn validate_jwt(token: &str) -> Result<Claims> {
    let validation = jwt::Validation::default();
    let data = jwt::decode::<Claims>(token, &JWT_ENCODING_KEY, &validation)?;
    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash() {
        let raw = "12345678";
        let hash = password_hash(raw).unwrap();

        assert_eq!(hash.len(), 97);
        assert!(hash.starts_with("$argon2id$v=19$m=65536,t=2,p=1$"));
    }

    #[test]
    fn test_password_verify() {
        let raw = "12345678";
        let hash = password_hash(raw).unwrap();

        assert_eq!(password_verify(raw, &hash), true);
        assert_eq!(password_verify(raw, "invalid hash"), false);
    }

    #[test]
    fn test_generate_jwt() {
        let claims = Claims::new(UserInfo::new("test".to_string(), false));
        let token = generate_jwt(claims).unwrap();
        assert_eq!(token.len(), 183);
    }

    #[test]
    fn test_validate_jwt() {
        let claims = Claims::new(UserInfo::new("test".to_string(), false));
        let token = generate_jwt(claims).unwrap();
        let claims = validate_jwt(&token).unwrap();
        assert_eq!(claims.user, UserInfo::new("test".to_string(), false));
    }
}
