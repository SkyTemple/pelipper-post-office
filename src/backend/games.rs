use std::collections::HashMap;

pub struct Game {
    pub code: String,
    key: String,
    ids: Vec<String>,
}

pub struct GamesBackend {
    games: HashMap<String, Game>,
}

impl GamesBackend {
    pub fn new() -> Self {
        let mut games = HashMap::new();
        // TODO database
        games.insert(
            "pokedungeonds".to_string(),
            Game {
                code: "pokedungeonds".to_string(),
                key: "SVbm3x".to_string(),
                ids: vec!["C2SE".to_string(), "C2SU".to_string(), "C2SJ".to_string()],
            },
        );
        Self { games }
    }

    pub fn contains(&self, gamecode: &str) -> bool {
        self.games.contains_key(gamecode)
    }

    pub async fn get_gamekey(&self, gamecode: &str) -> Option<&String> {
        self.games.get(gamecode).map(|g| &g.key)
    }

    pub async fn get_gameids(&self, gamecode: &str) -> Option<&Vec<String>> {
        self.games.get(gamecode).map(|g| &g.ids)
    }

    #[allow(clippy::ptr_arg)]
    pub async fn game_for_gameid(&self, game_id: &String) -> Option<&Game> {
        for game in self.games.values() {
            if game.ids.contains(game_id) {
                return Some(game);
            }
        }
        None
    }
}
