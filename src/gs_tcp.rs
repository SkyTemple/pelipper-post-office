use crate::backend::backends::BackendsRef;
use crate::backend::sessions::Session;
use crate::gs_tcp::MaybeFinal::{Final, Msg};
use crate::util::{md5sum, random_string};
use anyhow::{anyhow, Error};
use data_encoding::BASE64;
use indexmap::IndexMap;
use log::{debug, error, info, warn};
use std::collections::hash_map::Entry::Occupied;
use std::collections::HashMap;
use std::fmt::Display;
use std::iter::once;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

enum PeerState {
    WaitingForCr(String),
    LoggedIn(Session),
}

struct ReadInBuf {
    unread: usize,
    cursor: usize,
    buf: [u8; 10240],
}

const FINAL: &str = "final";
#[derive(Debug)]
enum MaybeFinal<T, U> {
    Final,
    Msg(T, U),
}

impl MaybeFinal<String, String> {
    pub fn as_ref(&self) -> MaybeFinal<&str, &str> {
        match self {
            Final => Final,
            Msg(a, b) => Msg(a, b),
        }
    }
}

async fn stream_read_single(
    stream: &mut TcpStream,
    buf: &mut ReadInBuf,
    reading_key: bool,
) -> Result<String, Error> {
    //debug!("String read request: reading_key: {}", reading_key);
    let mut string = Vec::with_capacity(50);
    'out: loop {
        if buf.unread < 1 {
            //debug!("GS TCP server; {:?}; Waiting...", stream.peer_addr());
            buf.unread += match stream.read(&mut buf.buf[buf.cursor..]).await {
                Ok(0) => return Err(anyhow!("Reached EOF.")),
                Ok(n) => n,
                Err(e) => return Err(e.into()),
            };
            //debug!("GS TCP server; {:?}; Read: {:?}", stream.peer_addr(), String::from_utf8(buf.buf[buf.cursor..buf.cursor + buf.unread].to_vec()));
        }
        let mut i = 0;
        let mut prekey = reading_key;
        for c in buf.buf[buf.cursor..buf.cursor + buf.unread].iter() {
            let char = *c as char;
            i += 1;
            if prekey {
                prekey = false;
                if char != '\\' {
                    return Err(anyhow!("Malformed key"));
                }
            } else if char == '\\' {
                if !reading_key {
                    i -= 1;
                }
                buf.cursor += i;
                buf.unread -= i;
                //debug!("GS TCP server; {:?}; Unread after: {}", stream.peer_addr(), buf.unread);
                break 'out;
            } else {
                string.push(char);
            }
        }
        buf.cursor += i;
        buf.unread -= i;
        //debug!("read part string: {}", string.iter().collect::<String>());
        //debug!("GS TCP server; {:?}; Unread after: {}", stream.peer_addr(), buf.unread);
    }
    let string = string.into_iter().collect();
    //debug!("read string: {}", string);
    Ok(string)
}

async fn stream_read_kv(
    stream: &mut TcpStream,
    buf: &mut ReadInBuf,
) -> Result<MaybeFinal<String, String>, Error> {
    let key = stream_read_single(stream, buf, true).await?;
    Ok(if key == FINAL {
        Final
    } else {
        Msg(key, stream_read_single(stream, buf, false).await?)
    })
}

async fn stream_read_collect_payload(
    stream: &mut TcpStream,
    buf: &mut ReadInBuf,
) -> Result<HashMap<String, String>, Error> {
    let mut collected = HashMap::new();
    while let Msg(k, v) = stream_read_kv(stream, buf).await? {
        collected.insert(k, v);
    }
    debug!("Read a client payload: {:?}", collected);
    Ok(collected)
}

async fn expect_final(stream: &mut TcpStream, buf: &mut ReadInBuf) -> Result<(), Error> {
    match stream_read_single(stream, buf, true).await?.as_ref() {
        FINAL => Ok(()),
        v => Err(anyhow!("Expected end of message (\\final), got: {}", v)),
    }
}

async fn send_err(
    stream: &mut TcpStream,
    fatal: bool,
    errmsg: &str,
    errcode: u32,
) -> Result<(), Error> {
    let mut cerr = IndexMap::new();
    let errcode_str = errcode.to_string();
    cerr.insert("error", "");
    cerr.insert("err", errcode_str.as_str());
    if fatal {
        cerr.insert("fatal", "");
    }
    cerr.insert("errmsg", errmsg);
    debug!(
        "GS TCP server; {:?}; Sending error: {:?}",
        stream.peer_addr(),
        cerr
    );
    stream.write_all(&make_response(cerr)).await?;
    Ok(())
}

fn generate_login_ticket() -> String {
    // \lt\Ne[EiaLbCydDhYmM]OHXac__ - A unique login ticket for this session.
    // Appears to be a base64-encoded random 16-byte string with "=", "+" and "/"
    // replaced by "_", "[" and "]" respectively.
    // It is not known if this ticket has any significance.
    let rn: [u8; 16] = random_string(0x00..0xFF);
    BASE64
        .encode(&rn)
        .replace('=', "_")
        .replace('+', "[")
        .replace('/', "]")
}

async fn login_peer(
    server_challenge: &str,
    stream: &mut TcpStream,
    buf: &mut ReadInBuf,
    backends: BackendsRef,
) -> Result<Session, Error> {
    let payload = stream_read_collect_payload(stream, buf).await?;
    debug!("Full login request: {:?}", payload);

    match payload.get("id") {
        Some(x) if x == "1" => {}
        _ => return Err(anyhow!("Invalid sequence id.")),
    }

    let bwrite = backends.write().await;
    if let Some(authtoken) = payload.get("authtoken") {
        if let Occupied(mut sess_entry) = bwrite
            .sessions
            .write()
            .await
            .get_waiting_entry(authtoken.to_string())
            .await
        {
            let session = sess_entry.get_mut();
            if let Some(user) = bwrite.users.write().await.get_user_mut(&session.user).await {
                let game_read = bwrite.games.read().await;
                let expected_gamecode = game_read
                    .game_for_gameid(&user.gs_account.gamecd)
                    .await
                    .map(|g| g.code.as_str())
                    .unwrap_or("");
                if payload.get("gamename").map(|x| x.as_str()) == Some(expected_gamecode) {
                    drop(game_read);
                    if let Some(client_challenge) = payload.get("challenge") {
                        if let Some(response) = payload.get("response") {
                            let expected_response = md5sum(
                                &(md5sum(&session.challenge)
                                    + &" ".repeat(48)
                                    + &session.token
                                    + client_challenge
                                    + server_challenge
                                    + &md5sum(&session.challenge)),
                            );
                            if response == &expected_response {
                                let proof = md5sum(
                                    &(md5sum(&session.challenge)
                                        + &" ".repeat(48)
                                        + &session.token
                                        + server_challenge
                                        + client_challenge
                                        + &md5sum(&session.challenge)),
                                );
                                // TODO: Seems to have no significance, but maybe it does and we have to also
                                //       update it regularly?
                                let lt = generate_login_ticket();
                                let (userid, profileid, uniquenick) =
                                    user.create_or_get_profilemeta().await?;
                                let userid = userid.to_string();
                                let profileid = profileid.to_string();
                                let sesskey = session.new_sesskey().await?;
                                let sesskey_str = sesskey.to_string();
                                let proof = &proof;
                                let mut rsp = IndexMap::new();
                                rsp.insert("lc", "2");
                                rsp.insert("sesskey", &sesskey_str);
                                rsp.insert("proof", proof);
                                rsp.insert("userid", &userid);
                                rsp.insert("profileid", &profileid);
                                rsp.insert("uniquenick", &uniquenick);
                                rsp.insert("lt", &lt);
                                rsp.insert("id", "1");
                                stream.write_all(&make_response(rsp)).await?;
                                Ok(sess_entry.remove())
                            } else {
                                Err(anyhow!("Failed CR."))
                            }
                        } else {
                            Err(anyhow!("'response' missing."))
                        }
                    } else {
                        Err(anyhow!("'challenge' missing."))
                    }
                } else {
                    debug!(
                        "Got game: {:?} -- expected:{}",
                        payload.get("gamename"),
                        expected_gamecode
                    );
                    Err(anyhow!("User game does not match requested game."))
                }
            } else {
                Err(anyhow!("User not found. Register first at nas."))
            }
        } else {
            Err(anyhow!("Invalid authtoken."))
        }
    } else {
        Err(anyhow!("authtoken missing."))
    }
}

async fn validate_profile_request(
    payload: &mut HashMap<String, String>,
    session: &Session,
    _stream: &mut TcpStream,
    _buf: &mut ReadInBuf,
    backends: &BackendsRef,
    validate_profile_id: bool,
) -> Result<String, Error> {
    let bread = backends.read().await;
    if let Some(sesskey) = payload.remove("sesskey") {
        let sesskey: i32 = match sesskey.parse() {
            Ok(v) => v,
            Err(_) => return Err(anyhow!("sesskey invalid.")),
        };
        if Some(sesskey) == session.sesskey {
            let uread = bread.users.read().await;
            let user = uread.get_user(&session.user).await;
            if validate_profile_id {
                if let Some(strprofileid) = payload.remove("profileid") {
                    let profileid: i32 = match strprofileid.parse() {
                        Ok(v) => v,
                        Err(_) => return Err(anyhow!("profileid invalid (1).")),
                    };
                    if user.map(|u| u.profileid) == Some(Some(profileid)) {
                        Ok(session.user.clone()) // designed this way, in case we need to allow access to other user's profiles here later too
                    } else {
                        debug!(
                            "Expected: {:?}, got {}",
                            user.map(|u| u.profileid),
                            profileid
                        );
                        Err(anyhow!("profileid invalid (2)."))
                    }
                } else {
                    Err(anyhow!("profileid missing."))
                }
            } else {
                Ok(session.user.clone())
            }
        } else {
            Err(anyhow!("sesskey invalid."))
        }
    } else {
        Err(anyhow!("sesskey missing."))
    }
}

async fn serve_profile(
    session: &Session,
    stream: &mut TcpStream,
    buf: &mut ReadInBuf,
    backends: BackendsRef,
) -> Result<(), Error> {
    let mut payload = stream_read_collect_payload(stream, buf).await?;
    let sequence_id = match payload.remove("id") {
        Some(x) => x,
        _ => return Err(anyhow!("Missing sequence id.")),
    };
    let unqiuenick =
        validate_profile_request(&mut payload, session, stream, buf, &backends, true).await?;
    let bread = backends.read().await;
    let uread = bread.users.read().await;
    let user = uread.get_user(&unqiuenick).await.unwrap();
    let profileid = user.profileid.unwrap().to_string();
    let userid = user.userid.unwrap().to_string();
    let mut rsp = IndexMap::new();
    let profile = user.profile().await?;
    rsp.insert("pi", "2".to_string());
    rsp.insert("profileid", profileid);
    rsp.insert("nick", unqiuenick);
    rsp.insert("userid", userid);
    rsp.extend(profile.into_iter());
    rsp.insert("id", sequence_id);
    stream.write_all(&make_response(rsp)).await?;
    Ok(())
}

async fn update_profile(
    session: &Session,
    stream: &mut TcpStream,
    buf: &mut ReadInBuf,
    backends: BackendsRef,
) -> Result<(), Error> {
    let mut payload = stream_read_collect_payload(stream, buf).await?;
    let unqiuenick =
        validate_profile_request(&mut payload, session, stream, buf, &backends, false).await?;
    let bwrite = backends.write().await;
    let mut uwrite = bwrite.users.write().await;
    let user = uwrite.get_user_mut(&unqiuenick).await.unwrap();
    for (k, v) in payload {
        match k.as_str() {
            "lastname" => {
                user.profile_update_lastname(v).await?;
            }
            v => debug!("User tried to set unknown profile field: {} => {}", k, v),
        }
    }
    Ok(())
}

fn make_response<T: Display>(m: IndexMap<&str, T>) -> Vec<u8> {
    let v = m
        .into_iter()
        .map(|(k, v)| format!("\\{}\\{}", k, v))
        .chain(once("\\final\\".to_string()))
        .collect::<String>();
    debug!("sending {}", v);
    v.into_bytes()
}

async fn process_socket(mut stream: TcpStream, backends: BackendsRef) -> Result<(), Error> {
    debug!(
        "GS TCP server; {:?}; connection established.",
        stream.peer_addr()
    );

    let ch: [char; 10] = random_string('A'..='Z');
    let challenge: String = ch.iter().collect();
    debug!(
        "GS TCP server; {:?}; sending challenge: {}",
        stream.peer_addr(),
        challenge
    );
    let mut creq = IndexMap::new();
    creq.insert("lc", "1");
    creq.insert("challenge", &challenge);
    creq.insert("id", "1");
    stream.write_all(&make_response(creq)).await?;

    let mut state = PeerState::WaitingForCr(challenge);

    let mut buf = ReadInBuf {
        unread: 0,
        cursor: 0,
        buf: [0; 10240],
    };
    loop {
        let res = stream_read_kv(&mut stream, &mut buf).await?;
        debug!(
            "GS TCP server; {:?}; command: {:?}",
            stream.peer_addr(),
            res
        );
        match res.as_ref() {
            Msg("login", "") => {
                if let PeerState::WaitingForCr(challenge) = &state {
                    match login_peer(challenge, &mut stream, &mut buf, backends.clone()).await {
                        Ok(session) => {
                            debug!(
                                "GS TCP server; {:?}; Successfully logged in.",
                                stream.peer_addr()
                            );
                            state = PeerState::LoggedIn(session);
                        }
                        Err(e) => {
                            debug!(
                                "GS TCP server; {:?}; Error during login: {} --\n{}",
                                stream.peer_addr(),
                                e,
                                e.backtrace()
                            );
                            send_err(&mut stream, false, &e.to_string(), 266).await?;
                        }
                    }
                } else {
                    debug!(
                        "GS TCP server; {:?}; Got login request when already logged in.",
                        stream.peer_addr()
                    );
                    send_err(&mut stream, false, "Already logged in.", 266).await?;
                }
            }
            Msg("getprofile", "") => {
                if let PeerState::LoggedIn(session) = &state {
                    match serve_profile(session, &mut stream, &mut buf, backends.clone()).await {
                        Ok(()) => {
                            debug!(
                                "GS TCP server; {:?}; Successfully sent profile.",
                                stream.peer_addr()
                            );
                        }
                        Err(e) => {
                            error!(
                                "GS TCP server; {:?}; Error sending profile: {} --\n{}",
                                stream.peer_addr(),
                                e,
                                e.backtrace()
                            );
                            send_err(&mut stream, false, &e.to_string(), 100).await?;
                        }
                    }
                } else {
                    debug!(
                        "GS TCP server; {:?}; Not authenticated for this.",
                        stream.peer_addr()
                    );
                    send_err(&mut stream, false, "Not authenticated.", 200).await?;
                }
            }
            Msg("updatepro", "") => {
                if let PeerState::LoggedIn(session) = &state {
                    match update_profile(session, &mut stream, &mut buf, backends.clone()).await {
                        Ok(()) => {
                            debug!(
                                "GS TCP server; {:?}; Successfully updated profile.",
                                stream.peer_addr()
                            );
                        }
                        Err(e) => {
                            error!(
                                "GS TCP server; {:?}; Error updating profile: {} --\n{}",
                                stream.peer_addr(),
                                e,
                                e.backtrace()
                            );
                            send_err(&mut stream, false, &e.to_string(), 100).await?;
                        }
                    }
                } else {
                    debug!(
                        "GS TCP server; {:?}; Not authenticated for this.",
                        stream.peer_addr()
                    );
                    send_err(&mut stream, false, "Not authenticated.", 200).await?;
                }
            }
            Msg("logout", "") => {
                // Logging out. We ignore the payload.
                let payload = stream_read_collect_payload(&mut stream, &mut buf).await?;
                debug!(
                    "GS TCP server; {:?}; Got LOGOUT with payload: {:?}",
                    stream.peer_addr(),
                    payload
                );
                return Ok(());
            }
            Msg("status", _status) => {
                // TODO: Process?
                let payload = stream_read_collect_payload(&mut stream, &mut buf).await?;
                debug!(
                    "GS TCP server; {:?}; Got a STATUS: {:?}",
                    stream.peer_addr(),
                    payload
                );
            }
            /*Msg("addbuddy", "") => {},
            Msg("delbuddy", "") => {},
            Msg("authadd", "") => {},
            Msg("bm", "1") => {},
            Msg("bm", "2") => {},*/
            Msg("ka", "") => {
                expect_final(&mut stream, &mut buf).await?;
                debug!(
                    "GS TCP server; {:?}; Got valid keep-alive.",
                    stream.peer_addr()
                );
            }
            //Msg("lt", lt) => {},
            Final => {
                warn!(
                    "GS TCP server; {:?}; Got an unexpected final message.",
                    stream.peer_addr()
                );
                send_err(&mut stream, true, "Invalid request.", 1).await?;
            }
            _ => {
                warn!(
                    "GS TCP server; {:?}; Ignoring unknown message '{:?}'.",
                    stream.peer_addr(),
                    res
                );
                send_err(&mut stream, true, "Invalid request.", 1).await?;
            }
        }
        // wrap cursor around
        if buf.cursor > 5120 {
            if buf.unread > 0 {
                let remaining = buf.buf[buf.cursor..buf.cursor + buf.unread].to_vec();
                buf.buf[0..buf.unread].copy_from_slice(&remaining);
            }
            buf.cursor = 0;
        }
    }
}

pub async fn run_gs_tcp(port: u16, backends: BackendsRef) -> Result<(), Error> {
    let listener = TcpListener::bind(&format!("0.0.0.0:{}", port)).await?;
    info!("GS TCP server listening on: {}", port);

    loop {
        let (stream, _) = listener.accept().await?;
        let br = backends.clone();
        tokio::spawn(async move {
            match process_socket(stream, br).await {
                Ok(_) => {}
                Err(e) => warn!(
                    "TCP Client connection closed due to error: {} -- \n{}",
                    e,
                    e.backtrace()
                ),
            }
        });
    }
}
