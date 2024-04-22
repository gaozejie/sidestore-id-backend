use crate::db::models::user::User;
use crate::db::Pool;
use crate::errors::ServiceError;

pub fn update_username(pool: &Pool, user_id: uuid::Uuid, new_username: &str) -> Result<(), ServiceError> {
    let conn = &mut pool.get().unwrap();

    let mut user = match User::find_by_id(&user_id, conn) {
        Ok(user) => user,
        Err(_) => return Err(ServiceError::Unauthorized { error_message: "User not found".to_string() })
    };

    // Update the username
    user.username = Some(new_username.to_string());
    user.update(conn)
        .map_err(|_| ServiceError::InternalServerError { error_message: "Failed to update username".to_string() })?;

    Ok(())
}