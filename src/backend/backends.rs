use crate::backend::games::GamesBackend;
use crate::backend::sessions::SessionsBackend;
use crate::backend::users::UsersBackend;
use std::sync::Arc;
use tokio::sync::RwLock;

pub type BackendsRef = Arc<RwLock<Backends>>;

pub struct Backends {
    pub games: Arc<RwLock<GamesBackend>>,
    pub users: Arc<RwLock<UsersBackend>>,
    pub sessions: Arc<RwLock<SessionsBackend>>,
}

impl Backends {
    pub fn new() -> Self {
        Self {
            games: Arc::new(RwLock::new(GamesBackend::new())),
            users: Arc::new(RwLock::new(UsersBackend::new())),
            sessions: Arc::new(RwLock::new(SessionsBackend::new())),
        }
    }
}
