use actix_web::{HttpResponse, web};
use validator::Validate;

use crate::api::utils::enforce_scope;
use crate::AppState;
use crate::auth::JwtTokenScope;
use crate::errors::ServiceError;
use crate::middlewares::auth::JwtMiddleware;
use crate::services::account_service;

use super::models::account::UsernameChangeRequest;
use super::models::MessageResponse;

#[utoipa::path(
    put,
    path = "/api/account/username",
    responses(
        (status = 200, response = MessageResponse)
    ),
    security(
        ("oauth" = [])
    )
)]
pub async fn update_username(body: web::Json<UsernameChangeRequest>, data: web::Data<AppState>, jwt: JwtMiddleware) -> Result<HttpResponse, ServiceError> {
    enforce_scope(&jwt, JwtTokenScope::Full)?;

    body.validate()
        .map_err(|e| ServiceError::from(e))?;

    account_service::update_username(&data.db, jwt.user_id, &body.new_username)?;

    Ok(HttpResponse::Ok().json(MessageResponse {
        message: "The username has been updated successfully".to_string()
    }))
}