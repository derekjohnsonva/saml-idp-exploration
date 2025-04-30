use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub user_id: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub mobile_phone: Option<String>,
    pub attributes: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserDatabase {
    pub users: Vec<User>,
}

impl UserDatabase {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let db: UserDatabase = serde_yaml::from_str(&contents)?;
        Ok(db)
    }

    pub fn find_user(&self, user_id: &str) -> Option<&User> {
        self.users.iter().find(|u| u.user_id == user_id)
    }
}
