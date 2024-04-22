use serde::{Deserialize, Serialize};
use utoipa::ToResponse;

pub mod auth;
pub mod app_reviews;
pub mod oauth2;
pub mod account;

#[derive(Serialize, Deserialize, ToResponse)]
pub struct MessageResponse {
    pub message: String,
}
