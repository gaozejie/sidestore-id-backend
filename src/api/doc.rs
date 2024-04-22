use utoipa::{Modify, OpenApi};
use utoipa::openapi::security::{AuthorizationCode, Flow, OAuth2, Scopes, SecurityScheme};

use crate::api::account_controller as Account;
use crate::api::app_review_controller as AppReviews;
use crate::api::auth_controller as Authentication;
use crate::api::models::account as AccountModels;
use crate::api::models::app_reviews as AppReviewModels;
use crate::api::models::auth as AuthModels;
use crate::api::models::MessageResponse as MessageResponse;
use crate::api::ping_controller as Health;
use crate::db::models as DBModels;
use crate::errors::ErrorResponse;

#[derive(OpenApi)]
#[openapi(
    info(title = "SideStore ID"),
    paths(
        Authentication::signup,
        Authentication::login,
        Authentication::refresh,
        Authentication::logout,
        Authentication::me,

        Authentication::change_user_password,

        Account::update_username,

        AppReviews::get_public_key,
        AppReviews::sign,
        AppReviews::get,
        AppReviews::delete,
        
        Health::ping,
    ),
    components(
        schemas(
            DBModels::user::User,

            AuthModels::LoginRequest,
            AuthModels::SignupRequest,
            AuthModels::PasswordChangeRequest,

            AccountModels::UsernameChangeRequest,

            AppReviewModels::AppReviewSignatureRequest,
            AppReviewModels::AppReviewDeletionRequest,
            AppReviewModels::UserAppReview,
            AppReviewModels::AppReviewStatus,
        ),
        responses(
            MessageResponse,
            ErrorResponse,

            AuthModels::LoginResponse,
            DBModels::user::User,

            AppReviewModels::AppReviewSignatureResponse,
            AppReviewModels::UserAppReviewList,
            AppReviewModels::UserAppReview,
            AppReviewModels::AppReviewStatus,
        ),
    ),
    modifiers(&SecurityAddon),
    tags(
        
    ),
)]
pub struct ApiDoc;

pub struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "oauth",
                SecurityScheme::OAuth2(OAuth2::new([
                    Flow::AuthorizationCode(AuthorizationCode::new(
                        "/api/auth/oauth2/authorize",
                        "/api/auth/oauth2/token",
                        Scopes::from_iter([("full", "full scope")])
                    )),
                ]))
            )
        }
    }
}
