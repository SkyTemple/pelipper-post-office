use crate::backend::games::GamesBackend;
use crate::util::{md5sum, userid_base32};
use anyhow::{anyhow, Error};
use indexmap::IndexMap;
use log::debug;
use rand::Rng;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use tokio::sync::RwLockReadGuard;

#[derive(Debug)]
pub struct GsAccount {
    apinfo: String,
    birth: (u8, u8),
    devname: String,
    ingamesn: Option<String>,
    pub gamecd: String,
    gsbrcd: Option<String>,
    lang: u8,
    macadr: String,
    makercd: u8,
    passwd: u16,
    sdkver: (u8, u8),
    unitcd: u32,
    pub userid: u64,
}

impl GsAccount {
    pub fn ident(&self) -> UserIdent {
        UserIdent {
            userid: self.userid,
            passwd: self.passwd,
            gamecd: self.gamecd.clone(),
        }
    }
}

#[derive(Debug)]
struct UserProfile {
    lastname: Option<String>,
}

impl UserProfile {
    fn new() -> Self {
        Self { lastname: None }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct UserIdent {
    userid: u64,
    passwd: u16,
    gamecd: String,
}

#[derive(Debug)]
pub struct UserInfo {
    pub gs_account: GsAccount,
    pub(crate) userid: Option<u32>,
    pub(crate) profileid: Option<i32>,
    profile: Option<UserProfile>,
}

impl UserInfo {
    pub fn ident(&self) -> UserIdent {
        self.gs_account.ident()
    }

    pub(crate) async fn profile(&self) -> Result<IndexMap<&'static str, String>, Error> {
        let r_profile = self.profile.as_ref().unwrap();
        let mut profile = IndexMap::new();
        let uniquenick = self.uniquenick();
        profile.insert("userid", self.userid.unwrap().to_string());
        profile.insert("email", format!("{}@nds", uniquenick));
        profile.insert("sig", md5sum("")); // TODO?
        profile.insert("uniquenick", uniquenick);
        if let Some(lastname) = &r_profile.lastname {
            profile.insert("lastname", lastname.clone());
        }
        profile.insert("pid", "11".to_string());
        profile.insert("lon", "0.000000".to_string());
        profile.insert("lat", "0.000000".to_string());
        profile.insert("loc", "".to_string());
        Ok(profile)
    }

    pub fn uniquenick(&self) -> String {
        format!("{}+{}", self.gs_account.userid, self.gs_account.gamecd)
    }

    pub(crate) async fn profile_update_lastname(&mut self, value: String) -> Result<(), Error> {
        self.profile.as_mut().unwrap().lastname = Some(value);
        Ok(())
    }

    pub(crate) async fn create_or_get_profilemeta(&mut self) -> Result<(u32, i32, String), Error> {
        let mut rng = rand::thread_rng();

        // \userid\443357202 - A unique userid. Unclear how this value is calculated,
        // but uniqueness is probably sufficient.
        let userid = match self.userid {
            Some(v) => v,
            None => {
                let v = rng.gen_range(0..449999999);
                self.userid = Some(v);
                v
            }
        };

        // \profileid\475475956 - The unique profileid.
        // It does not need to be the same as the userid.
        // This ID serves as the 32 least-significant bits of the friend code.
        // The highest 7 bits of the friend code are a checksum.
        let profileid = match self.profileid {
            Some(v) => v,
            None => {
                let v = rng.gen::<i32>().abs();
                self.profileid = Some(v);
                v
            }
        };

        if self.profile.is_none() {
            self.profile = Some(UserProfile::new());
        }

        Ok((userid, profileid, self.uniquenick()))
    }
}

pub struct UsersBackend {
    // TODO: replace with a db!
    users: HashMap<UserIdent, UserInfo>,
}

impl UsersBackend {
    pub fn new() -> Self {
        // TODO
        Self {
            users: HashMap::new(),
        }
    }

    pub async fn get_user(&self, query: &UserIdent) -> Option<&UserInfo> {
        self.users.get(query)
    }

    pub async fn get_user_mut(&mut self, query: &UserIdent) -> Option<&mut UserInfo> {
        self.users.get_mut(query)
    }

    pub async fn create_or_loadfrom_hashmap(
        &mut self,
        gs_input_data: HashMap<String, String>,
        games: RwLockReadGuard<'_, GamesBackend>,
    ) -> Result<&UserInfo, Error> {
        let action_owned = gs_input_data.get("action").cloned();
        let action = action_owned.as_deref();
        if action != Some("login") && action != Some("acctcreate") {
            dbg!(&gs_input_data);
            return Err(anyhow!(
                "Invalid user creation request: 'action' must be 'login' or 'acctcreate', is: {:?}",
                gs_input_data.get("action")
            ));
        }
        let mut apinfo: Option<String> = None;
        let mut birth: Option<(u8, u8)> = None;
        let mut devname: Option<String> = None;
        let mut ingamesn: Option<String> = None;
        let mut gamecd: Option<String> = None;
        let mut gsbrcd: Option<String> = None;
        let mut lang: Option<u8> = None;
        let mut macadr: Option<String> = None;
        let mut makercd: Option<u8> = None;
        let mut passwd: Option<u16> = None;
        let mut sdkver: Option<(u8, u8)> = None;
        let mut unitcd: Option<u32> = None;
        let mut userid: Option<u64> = None;
        for (k, v) in gs_input_data {
            match k.as_str() {
                "apinfo" => apinfo = Some(v),
                "birth" => {
                    if v.len() != 4 {
                        return Err(anyhow!("Invalid 'birth': {}", v));
                    }
                    let month = u8::from_str_radix(&v[0..2], 16)?;
                    let day = u8::from_str_radix(&v[2..4], 16)?;
                    birth = Some((month, day))
                }
                "devname" => devname = Some(v),
                "ingamesn" => ingamesn = Some(v),
                "gamecd" => {
                    if games.game_for_gameid(&v).await.is_none() {
                        return Err(anyhow!("Game {} not supported.", v));
                    }
                    gamecd = Some(v)
                }
                "gsbrcd" => gsbrcd = Some(v),
                "lang" => {
                    if v.len() != 2 {
                        return Err(anyhow!("Invalid 'lang': {}", v));
                    }
                    lang = Some(u8::from_str_radix(&v, 16)?)
                }
                "macadr" => macadr = Some(v),
                "makercd" => {
                    if v.len() != 2 {
                        return Err(anyhow!("Invalid 'makercd': {}", v));
                    }
                    makercd = Some(u8::from_str_radix(&v, 16)?)
                }
                "passwd" => passwd = Some(v.parse::<u16>()?),
                "sdkver" => {
                    if v.len() != 6 {
                        return Err(anyhow!("Invalid 'sdkver': {}", v));
                    }
                    let major = v[0..3].parse::<u8>()?;
                    let minor = v[3..6].parse::<u8>()?;
                    sdkver = Some((major, minor))
                }
                "unitcd" => unitcd = Some(v.parse::<u32>()?),
                "userid" => userid = Some(v.parse::<u64>()?), // TODO: Assert < 32pow10
                _ => {}
            }
        }
        let userid = unpack_or_err(userid, "userid")?;
        let gs_account = GsAccount {
            apinfo: unpack_or_err(apinfo, "apinfo")?,
            birth: unpack_or_err(birth, "birth")?,
            devname: unpack_or_err(devname, "devname")?,
            ingamesn,
            gamecd: unpack_or_err(gamecd, "gamecd")?,
            gsbrcd,
            lang: unpack_or_err(lang, "lang")?,
            macadr: unpack_or_err(macadr, "macadr")?,
            makercd: unpack_or_err(makercd, "makercd")?,
            passwd: unpack_or_err(passwd, "passwd")?,
            sdkver: unpack_or_err(sdkver, "sdkver")?,
            unitcd: unpack_or_err(unitcd, "unitcd")?,
            userid,
        };
        let user_ident = gs_account.ident();
        match self.users.entry(user_ident.clone()) {
            Entry::Occupied(oe) => {
                let oe_u = oe.into_mut();
                if action == Some("acctcreate") {
                    let user = UserInfo {
                        gs_account,
                        userid: None,
                        profileid: None,
                        profile: None,
                    };
                    *oe_u = user;
                    debug!("Recreated profile profile: {:?}", oe_u);
                } else {
                    oe_u.gs_account = gs_account;
                    debug!("Loaded and updated existing profile: {:?}", oe_u);
                }
            }
            Entry::Vacant(ve) => {
                let user = UserInfo {
                    gs_account,
                    userid: None,
                    profileid: None,
                    profile: None,
                };
                // TODO: Replace with db insert.
                debug!("Created new profile: {:?}", user);
                ve.insert(user);
            }
        };
        Ok(self.users.get(&user_ident).unwrap())
    }
}

fn unpack_or_err<T>(val: Option<T>, name: &str) -> Result<T, Error> {
    match val {
        None => Err(anyhow!("Field '{}' missing.", name)),
        Some(v) => Ok(v),
    }
}
