use std::collections::BTreeMap;
use std::iter::once;
use std::num::NonZeroUsize;
use anyhow::{anyhow, Error};
use clru::CLruCache;
use log::{debug, info, warn};
use packed_struct::EnumCatchAll::Enum;
use tokio::net::UdpSocket;
use packed_struct::prelude::*;
use packed_struct::prelude::bits::ByteArray;
use std::net::{IpAddr, SocketAddr};
use bytes::{Buf, Bytes};
use futures::FutureExt;
use itertools::Itertools;
use crate::backend::backends::BackendsRef;
use crate::gs_udp::MessageType::*;
use crate::util::{advance_nul, decode_cr, random_string};

// see http://www.pipian.net/ierukana/hacking/ds_nwc.html
#[derive(PrimitiveEnum_u8, Clone, Copy, Debug, PartialEq)]
pub enum MessageType {
    ChallengeResponse = 0x1,
    Heartbeat = 0x3,
    KeepAlive = 0x8,
    Available = 0x9,
    ResponseCorrect = 0xA,
}

#[derive(PackedStruct)]
#[packed_struct(bit_numbering="msb0", endian="msb")]
pub struct ClientDatagramHeader {
    #[packed_field(bytes="0", ty="enum")]
    message_type: EnumCatchAll<MessageType>,
    #[packed_field(bytes="1..=4")]
    client_id: u32,     // An ID provided by the client.
                        // It is unknown if this is unique per user or per session.
    // After: The payload of the datagram.
}

#[derive(PackedStruct)]
#[packed_struct(bit_numbering="msb0", endian="msb")]
pub struct ServerDatagramHeader {
    #[packed_field(bytes="0..=1")]
    ack: u16,       // Always 0xFEFD in network byte order (i.e. "\xfe\xfd")
    #[packed_field(bytes="2", ty="enum")]
    message_type: MessageType,
    #[packed_field(bytes="3..=6")]
    client_id: u32, // The ID previously provided by the client.
    // After: The payload of the datagram.
}

#[derive(PartialEq)]
enum PeerStateType {
    WaitingCR, Connected
}

struct PeerState {
    state: PeerStateType,
    heartbeat_registration_data: BTreeMap<String, String>,
    challenge: [u8; 6]
}

impl PeerState {
    fn new(heartbeat_registration_data: BTreeMap<String, String>) -> Self {
        Self { state: PeerStateType::WaitingCR, heartbeat_registration_data, challenge: random_string(0x21..=0x7F) }
    }

    fn update_heartbeat(&mut self, new_beat: BTreeMap<String, String>) {
        self.heartbeat_registration_data.extend(new_beat)
    }

    fn get_gamename(&self) -> Option<&String> {
        self.heartbeat_registration_data.get("gamename")
    }

    /// Syncs the data provided by the peer to the backends.
    fn sync(&self, _backends: BackendsRef) {
        // TODO ?
    }
}

struct UdpServer {
    backends: BackendsRef,
    socket: UdpSocket,
    recv_buf: [u8; 10240],
    peers: CLruCache<u32, PeerState>
}


fn read_payload(mut msg: Bytes) -> Result<BTreeMap<String, String>, Error> {
    let mut res = BTreeMap::new();
    while msg.has_remaining() {
        if let Some(raw_str) = advance_nul(&mut msg) {
            let key = String::from_utf8(raw_str)?;
            if let Some(raw_str) = advance_nul(&mut msg) {
                let value = String::from_utf8(raw_str)?;
                res.insert(key, value);
            } else {
                return Err(anyhow!("Payload contained a key without a value."));
            }
        }
    }
    Ok(res)
}

fn make_empty_server_datagram(message_type: MessageType, client_id: u32) -> Result<[u8; 7], PackingError> {
    ServerDatagramHeader {
        ack: 0xFEFD,
        message_type,
        client_id
    }.pack()
}

fn make_server_datagram(message_type: MessageType, client_id: u32, body: &[u8]) -> Result<Vec<u8>, PackingError> {
    let data = make_empty_server_datagram(message_type, client_id)?
        .iter()
        .chain(body)
        .copied()
        .collect();
    debug!("GS UDP: Sending {:02X?}", data);
    Ok(data)
}

async fn handle_available(srv: &mut UdpServer, peer: SocketAddr, header: ClientDatagramHeader, msg: Bytes) -> Result<(), Error> {
    // TODO: It seems the game doesn't actually send the gamename.
    //       So we just report back it's available. The game ignores the answer anyway.
    debug!("GS UDP: Sending available response.");
    let resp = make_empty_server_datagram(Available, header.client_id)?;
    match srv.socket.send_to(&resp, peer).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into())
    }
}

async fn handle_heartbeat(srv: &mut UdpServer, peer: SocketAddr, header: ClientDatagramHeader, msg: Bytes) -> Result<(), Error> {
    debug!("GS UDP: Got a heartbeat from {}.", header.client_id);
    let client_was_known = srv.peers.contains(&header.client_id);
    let data = read_payload(msg)?;
    debug!("GS UDP: Registered client with data: {:?}. Was known before?: {}", data, client_was_known);
    srv.peers.put_or_modify(
        header.client_id,
        |_, v| PeerState::new(v),
        |_, ov, nv| ov.update_heartbeat(nv),
        data
    );
    let peer_state = srv.peers.get_mut(&header.client_id).unwrap();
    peer_state.sync(srv.backends.clone());
    if !client_was_known {
        debug!("GS UDP: Sending challenge response");
        // The payload of a CHALLENGE_RESPONSE datagram from the server contains five
        // concatenated values (with no separators):
        //
        // A random 6-byte string (with byte values taken from the range 0x21 to 0x7F)
        // The string 00
        // The hexadecimal string inet_aton(external_ip) (to replace the value of publicip in
        //    future HEARTBEAT datagrams)
        // The hexadecimal string htons(external_port) (to replace the value of publicport in
        //    future HEARTBEAT datagrams)
        // A single NULL byte as terminator.
        let ipocts = match peer.ip() {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(_) => return Err(anyhow!("Client connected via Ipv6, this is currently not supported.")),
        };
        let ipocts_bytes = ipocts.into_iter().map(|x| format!("{:02X}", x).as_bytes().to_vec()).flatten().collect_vec();
        let port_bytes = peer.port().to_be_bytes().into_iter().map(|x| format!("{:02X}", x).as_bytes().to_vec()).flatten().collect_vec();
        let body = peer_state.challenge.iter()
            .chain(b"00")
            .copied()
            .chain(ipocts_bytes.into_iter())
            .chain(port_bytes.into_iter())
            .chain(once(0))
            .collect::<Vec<u8>>();
        match srv.socket.send_to(&make_server_datagram(ChallengeResponse, header.client_id, &body)?, peer).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into())
        }
    } else {
        Ok(())
    }
}

async fn handle_challenge_response(
    srv: &mut UdpServer, peer: SocketAddr,
    header: ClientDatagramHeader, mut msg: Bytes
) -> Result<(), Error> {

    let peer_state: &mut PeerState;
    if let Some(ps) = srv.peers.get_mut(&header.client_id) {
        peer_state = ps;
    } else {
        return Err(anyhow!("Challenge response failed. Unknown client ID."))
    }

    if peer_state.state == PeerStateType::WaitingCR {
        // TODO: Challenge response is always empty?
        debug!("Challenge response succeeded. Replying with ResponseCorrect...");
        peer_state.state = PeerStateType::Connected;
        match srv.socket.send_to(&make_empty_server_datagram(ResponseCorrect, header.client_id)?, peer).await {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into())
        }
        /*
        if let Some(cr) = advance_nul(&mut msg) {
            if let Some(gamename) = peer_state.get_gamename() {
                if let Some(gamekey) = srv.backends.read().await.games.read().await.get_gamekey(gamename).await {
                    if decode_cr(&cr, gamekey.as_bytes()) == Some(peer_state.challenge.to_vec()) {
                        debug!("Challenge response succeeded. Replying with ResponseCorrect...");
                        peer_state.state = PeerStateType::Connected;
                        match srv.socket.send_to(&make_empty_server_datagram(ResponseCorrect, header.client_id)?, peer).await {
                            Ok(_) => Ok(()),
                            Err(e) => Err(e.into())
                        }
                    } else {
                        Err(anyhow!("Challenge response failed. Invalid response."))
                    }
                } else {
                    Err(anyhow!("Client specified unknown gamename: {}", gamename))
                }
            } else {
                Err(anyhow!("Client did not specify a game to connect for."))
            }
        } else {
            Err(anyhow!("Payload contained invalidly formatted challenge response."))
        }
        */
    } else {
        debug!("Did not expect CR. Ignoring");
        Ok(())
    }
}

async fn process_msg(srv: &mut UdpServer) -> Result<(), Error> {
    let header_len = <ClientDatagramHeader as PackedStruct>::ByteArray::len();
    let (size, peer) = srv.socket.recv_from(&mut srv.recv_buf[0..header_len]).await?;
    let header = ClientDatagramHeader::unpack_from_slice(&srv.recv_buf[..header_len])?;
    let msg = Bytes::copy_from_slice(&srv.recv_buf[header_len..size]);
    debug!("GS UDP: Received {:?} from {}/{}: {:02X?} - Bytes remaining: {}", header.message_type, peer, header.client_id, &srv.recv_buf[..size], msg.len());
    match header.message_type {
        Enum(Available) => handle_available(srv, peer, header, msg).await?,
        Enum(Heartbeat) => handle_heartbeat(srv, peer, header, msg).await?,
        Enum(ChallengeResponse) => handle_challenge_response(srv, peer, header, msg).await?,
        Enum(KeepAlive) => {srv.peers.get(&header.client_id);},
        _ => debug!("GS UDP: Message unknown / invalid.")
    }
    Ok(())
}

pub async fn run_gs_udp(port: u16, backends: BackendsRef) -> Result<(), Error> {
    let mut srv = UdpServer {
        backends,
        socket: UdpSocket::bind(&format!("0.0.0.0:{}", port)).await?,
        recv_buf: [0; 10240],
        peers: CLruCache::new(NonZeroUsize::new(10000).unwrap())
    };
    info!("GS UDP server listening on: {}", port);
    loop {
        if let Err(e) = process_msg(&mut srv).await {
            warn!("Error processing a message: {} -- \n{}", e, e.backtrace());
        }
    }
}
