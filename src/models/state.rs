use samael::idp;
use std::sync::Arc;
use crate::models::user::UserDatabase;

pub struct AppState {
    pub idp: Arc<idp::IdentityProvider>,
    pub cert_der: Vec<u8>,
    pub idp_entity_id: String,
    pub sp_entity_id: String,
    pub sp_acs_url: String,
    pub user_database: UserDatabase,
}

