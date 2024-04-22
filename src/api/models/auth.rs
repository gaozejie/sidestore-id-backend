use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use utoipa::{ToResponse, ToSchema};
use validator::{Validate, ValidationError};

use crate::db::models::user::User;

lazy_static! {
     static ref RE_SPECIAL_CHAR: Regex = Regex::new("^.*?[@$!%*?&].*$").unwrap();
 }

fn validate_password(password: &str) -> Result<(), ValidationError> {
    let mut has_whitespace = false;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;

    for c in password.chars() {
        has_whitespace |= c.is_whitespace();
        has_lower |= c.is_lowercase();
        has_upper |= c.is_uppercase();
        has_digit |= c.is_digit(10);
    }
    if !has_whitespace && has_upper && has_lower && has_digit && password.len() >= 8 {
        Ok(())
    } else {
        return Err(ValidationError::new("Password validation failed."));
    }
}

#[derive(Deserialize, Validate, ToSchema)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    pub password: String,
}

#[derive(Serialize, ToResponse)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub profile: User,
}

#[derive(Deserialize, Validate, ToSchema)]
pub struct SignupRequest {
    #[validate(email)]
    pub email: String,

    #[validate(
        custom(
            function = "validate_password",
            message = "The password must contain at least one uppercase and lowercase character, at least one digit, no spaces, and has to be at least eight characters long"
        ),
        regex(
            path = "*RE_SPECIAL_CHAR",
            message = "The password must contain at least one special character"
        )
    )]
    pub password: String,
}

pub type SignupResponse = LoginResponse;

#[derive(Deserialize, Validate, ToSchema)]
pub struct PasswordChangeRequest {
    pub current_password: String,
    #[validate(
        custom(
            function = "validate_password",
            message = "The password must contain at least one uppercase and lowercase character, at least one digit, no spaces, and has to be at least eight characters long"
        ),
        regex(
            path = "*RE_SPECIAL_CHAR",
            message = "The password must contain at least one special character"
        )
    )]
    pub new_password: String,
}
