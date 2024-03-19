use utoipa::OpenApi;
use crate::api::auth_controller as Authentication;
use crate::api::app_review_controller as AppReviews;
use crate::api::ping_controller as Health;
use crate::api::models::auth as AuthModels;
use crate::api::models::app_reviews as AppReviewModels;
use crate::db::models as DBModels;
use crate::api::models::MessageResponse;
use crate::errors::ErrorResponse;

#[derive(OpenApi)]
#[openapi(
    info(description = "SideStore ID"),
    paths(
        Authentication::signup,
        Authentication::login,
        Authentication::refresh,
        Authentication::logout,
        Authentication::me,

        Authentication::change_user_password,

        AppReviews::get_public_key,
        AppReviews::sign,
        AppReviews::get,
        AppReviews::delete,
        
        Health::ping,
    ),
    components(
        schemas(
            AuthModels::LoginRequest,
            AuthModels::SignupRequest,
            AuthModels::PasswordChangeRequest,

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
)]
pub struct ApiDoc;
