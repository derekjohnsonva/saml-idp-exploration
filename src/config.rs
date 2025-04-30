use actix_web::web;
use log::{error, info};
use std::env;
use std::sync::Arc;

use crate::cert_util::load_or_create_identity_provider;
use crate::models::state::AppState;
use crate::models::user::UserDatabase;

pub fn create_app_state() -> Result<web::Data<AppState>, Box<dyn std::error::Error>> {
    // Load or create identity provider
    let (idp, cert_der) = load_or_create_identity_provider()?;

    info!(
        "IdP initialized with certificate of size: {} bytes",
        cert_der.len()
    );

    // Get configuration from environment variables
    let idp_entity_id =
        env::var("IDP_ENTITY_ID").map_err(|_| "IDP_ENTITY_ID environment variable is not set")?;
    let sp_entity_id =
        env::var("SP_ENTITY_ID").map_err(|_| "SP_ENTITY_ID environment variable is not set")?;
    let sp_acs_url =
        env::var("SP_ACS_URL").map_err(|_| "SP_ACS_URL environment variable is not set")?;
    let user_database_path = env::var("USER_DATABASE_PATH")
        .map_err(|_| "USER_DATABASE_PATH environment variable is not set")?;

    // Load user database
    let user_database = UserDatabase::load_from_file(&user_database_path).map_err(|e| {
        error!("Failed to load user database: {}", e);
        format!("Failed to load user database: {}", e)
    })?;

    info!(
        "Loaded user database with {} users",
        user_database.users.len()
    );

    // Create AppState with configuration
    Ok(web::Data::new(AppState {
        idp: Arc::new(idp),
        cert_der,
        idp_entity_id,
        sp_entity_id,
        sp_acs_url,
        user_database,
    }))
}
