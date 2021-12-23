use std::collections::hash_map::Entry;
use std::collections::HashMap;
use anyhow::{anyhow, Error};
use data_encoding::BASE64;
use rand::Rng;
use crate::backend::users::UserInfo;
use crate::util::random_string;

#[derive(Debug)]
pub struct Session {
    pub(crate) user: String,

    pub(crate) challenge: String,
    pub(crate) token: String,
    pub(crate) sesskey: Option<i32>,
}

impl Session {
    pub(crate) async fn new_sesskey(&mut self) -> Result<i32, Error> {
        let mut rng = rand::thread_rng();
        let key = rng.gen::<u16>() as i32;
        self.sesskey = Some(key);
        Ok(key)
    }
}

pub struct SessionsBackend {
    // TODO: replace with redis?
    sessions_waiting: HashMap<String, Session>,  // token, Session
    // Established sessions get taken out and assigned to TCP connections.
}

impl SessionsBackend {
    pub fn new() -> Self {
        Self {
            sessions_waiting: HashMap::new(),
        }
    }

    pub async fn new_for(&mut self, user: &UserInfo) -> &Session {
        let challenge = Self::generate_challenge();
        let token = Self::generate_token();
        self.sessions_waiting.insert(
            token.clone(), Session {
                user: user.uniquenick.clone(),
                challenge,
                token: token.clone(),
                sesskey: None
            }
        );
        self.sessions_waiting.get(&token).unwrap()
    }

    pub async fn get_waiting_entry(&mut self, token: String) -> Entry<'_, String, Session> {
        self.sessions_waiting.entry(token)
    }

    fn generate_challenge() -> String {
        // A random 8-character challenge string (upper-case ASCII only)
        // to be used as the password when logging in to GameSpy for this session
        let ch: [char; 8] = random_string('A'..='Z');
        ch.iter().collect()
    }

    fn generate_token() -> String {
        // An authentication token to present to the GameSpy servers as the username for
        // this session. Appears to be a random string of 96 bytes, which is then
        // base64-encoded and prefixed by "NDS"
        let ch: [u8; 96] = random_string(0x00..0xFF);
        return "NDS".chars().chain(BASE64.encode(&ch).chars()).collect()
    }
}
