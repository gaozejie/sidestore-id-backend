use serde::Deserialize;
use utoipa::ToSchema;
use validator::{Validate, ValidationError};

fn validate_password(password: &str) -> Result<(), ValidationError> {
    let mut has_whitespace = false;
    let mut has_special_char = false;

    for c in password.chars() {
        has_whitespace |= c.is_whitespace();
        has_special_char |= !c.is_alphanumeric()
    }
    if !has_whitespace && has_special_char && password.len() >= 3 {
        Ok(())
    } else {
        return Err(ValidationError::new("Username validation failed."));
    }
}

#[derive(Deserialize, Validate, ToSchema)]
pub struct UsernameChangeRequest {
    #[validate(
        custom(
            function = "validate_password",
            message = "The password must only contain alphanumeric characters, and no whitespaces are allowed."
        )
    )]
    pub new_username: String,
}
