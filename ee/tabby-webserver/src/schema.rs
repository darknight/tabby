use juniper::{graphql_object, EmptySubscription, FieldResult, RootNode};

use crate::{api::Worker, server::ServerContext};
use crate::authentication::{AuthenticationService, LoginInput, LoginResponse, RefreshTokenResponse, RegisterInput, RegisterResponse, VerifyAccessTokenResponse};

// To make our context usable by Juniper, we have to implement a marker trait.
impl juniper::Context for ServerContext {}

#[derive(Default)]
pub struct Query;

#[graphql_object(context = ServerContext)]
impl Query {
    async fn workers(ctx: &ServerContext) -> Vec<Worker> {
        ctx.list_workers().await
    }

    async fn registration_token(ctx: &ServerContext) -> FieldResult<String> {
        let token = ctx.read_registration_token().await?;
        Ok(token)
    }
}

#[derive(Default)]
pub struct Mutation;

#[graphql_object(context = ServerContext)]
impl Mutation {
    async fn reset_registration_token(ctx: &ServerContext) -> FieldResult<String> {
        let token = ctx.reset_registration_token().await?;
        Ok(token)
    }

    async fn user_register(ctx: &ServerContext, input: RegisterInput) -> FieldResult<RegisterResponse> {
        let resp = ctx.register(input).await?;
        Ok(resp)
    }

    async fn user_login(ctx: &ServerContext, input: LoginInput) -> FieldResult<LoginResponse> {
        let resp = ctx.login(input).await?;
        Ok(resp)
    }

    async fn refresh_token(ctx: &ServerContext,
                           refresh_token: String) -> FieldResult<RefreshTokenResponse> {
        let resp = ctx.refresh_token(refresh_token).await?;
        Ok(resp)
    }

    async fn verify_token(ctx: &ServerContext,
                          access_token: String) -> FieldResult<VerifyAccessTokenResponse> {
        let resp = ctx.verify_token(access_token).await?;
        Ok(resp)
    }
}

pub type Schema = RootNode<'static, Query, Mutation, EmptySubscription<ServerContext>>;

pub fn create_schema() -> Schema {
    Schema::new(Query, Mutation, EmptySubscription::new())
}
