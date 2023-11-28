mod resolve;

use std::sync::Arc;
use anyhow::Result;
use axum::{
    Router,
    http::{Request, StatusCode},
    routing::get,
    response::{IntoResponse, Response},
    middleware::{self, Next},
    extract::Extension,
};
use axum::{extract::Path, routing, Json};
use axum::handler::Handler;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::extract::{State, TypedHeader};
use axum::headers::Authorization;
use axum::headers::authorization::Bearer;
use tower::ServiceBuilder;
use tabby_common::path::repositories_dir;
use tracing::{debug, instrument, warn};

use crate::{
    repositories,
    repositories::resolve::{resolve_dir, resolve_file, resolve_meta, Meta, ResolveParams},
};
use crate::authentication::{UserInfo, validate_jwt};
use crate::authorization::{AuthorizationService, Permission};
use crate::server::ServerContext;

pub fn routes(ctx: Arc<ServerContext>) -> Router {
    Router::new()
        .route("/:name/resolve/", routing::get(repositories::resolve))
        .route("/:name/resolve/*path", routing::get(repositories::resolve))
        .route_layer(
            ServiceBuilder::new()
                .layer(from_fn(auth))
                .layer(Extension(vec!["repo.resolve.view".to_string()]))
                .layer(from_fn_with_state(ctx.clone(), authorize))
        )
        .route("/:name/meta/", routing::get(repositories::meta))
        .route("/:name/meta/*path", routing::get(repositories::meta))
        .route_layer(
            ServiceBuilder::new()
                .layer(from_fn(auth))
                .layer(Extension(vec!["repo.meta.view".to_string()]))
                .layer(from_fn_with_state(ctx.clone(), authorize))
        )
}

async fn auth<B>(
    TypedHeader(header): TypedHeader<Authorization<Bearer>>,
    mut request: Request<B>,
    next: Next<B>
) -> Result<Response, StatusCode> {
    match validate_jwt(header.token()) {
        Ok(claims) => {
            request.extensions_mut().insert(claims.user_info());
            Ok(next.run(request).await)
        },
        Err(_) => Err(StatusCode::UNAUTHORIZED)
    }
}

async fn authorize<B>(
    Extension(user): Extension<UserInfo>,
    Extension(perms): Extension<Vec<String>>,
    State(state): State<Arc<ServerContext>>,
    request: Request<B>,
    next: Next<B>
) -> Result<Response, StatusCode> {
    debug!("authorize: {:?} {:?}", user, perms);
    let perms = perms.iter().map(|p| p.into()).collect::<Vec<_>>();
    if user.is_superuser() || state.has_all_permissions(&user, &perms).await.unwrap_or(false) {
        Ok(next.run(request).await)
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

#[instrument(skip(repo))]
async fn resolve(Path(repo): Path<ResolveParams>) -> Result<Response, StatusCode> {
    let root = repositories_dir().join(repo.name_str());
    let full_path = root.join(repo.path_str());
    let is_dir = tokio::fs::metadata(full_path.clone())
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false);

    if is_dir {
        return match resolve_dir(root, full_path.clone()).await {
            Ok(resp) => Ok(resp),
            Err(err) => {
                warn!("failed to resolve_dir <{:?}>: {}", full_path, err);
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        };
    }

    match resolve_file(root, &repo).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            warn!("failed to resolve_file <{:?}>: {}", full_path, err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[instrument(skip(repo))]
async fn meta(Path(repo): Path<ResolveParams>) -> Result<Json<Meta>, StatusCode> {
    let key = repo.dataset_key();
    if let Some(resp) = resolve_meta(&key) {
        return Ok(Json(resp));
    }
    Err(StatusCode::NOT_FOUND)
}
