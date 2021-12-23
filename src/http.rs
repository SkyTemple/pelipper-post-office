use std::collections::HashMap;
use std::net::{SocketAddr};
use anyhow::{anyhow, Error};
use chrono::Utc;
use const_format::concatcp;
use data_encoding::{BASE64, DecodeError};
//use async_stream::{AsyncStream, stream};
use hyper::{Body, body, Method, Request, Response, Server, StatusCode};
use hyper::service::{make_service_fn, service_fn};
use itertools::Itertools;
use log::{debug, info, warn};
use tokio::sync::RwLockWriteGuard;
use crate::backend::backends::BackendsRef;
use crate::backend::sessions::SessionsBackend;
use crate::backend::users::UserInfo;
use crate::util::VERSION;
//use tokio_native_tls::native_tls::{Identity, Protocol};
//use tokio_native_tls::{native_tls, TlsAcceptor, TlsStream};

fn extract_host(req: &Request<Body>) -> String {
    match req.headers().get("Host").map(|x| x.to_str()) {
        Some(Ok(v)) => {
            v.to_string()
        },
        _ => {
            req.uri().host().unwrap_or("???").to_string()
        }
    }
}

#[inline]
fn base64_decode(inp: &str) -> Result<Vec<u8>, DecodeError> {
    BASE64.decode(inp
        .replace('*', "=")
        .replace('-', "/")
        .replace('_', "+")
        .as_bytes()
    )
}

#[inline]
fn base64_encode(inp: &str) -> String {
    BASE64.encode(inp.as_bytes())
        .replace('=', "*")
        .replace('/', "-")
        .replace('+', "_")
}

async fn parse_request_body(req: &mut Request<Body>) -> Result<HashMap<String, String>, Error> {
    let body = String::from_utf8(body::to_bytes(req.body_mut()).await?.to_vec())?;
    let mut parsed = HashMap::new();
    for kv in body.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == "devname" || k == "ingamesn" {
                let mut b64u16: Vec<u16> = Vec::with_capacity(v.len());
                for (b1, b2) in base64_decode(v)?.into_iter().tuples() {
                    b64u16.push((b1) as u16 + (((b2) as u16) << 8))
                }
                parsed.insert(
                    k.to_string(),
                    String::from_utf16(&b64u16)?
                );
            } else {
                parsed.insert(
                    k.to_string(),
                    String::from_utf8(base64_decode(v)?)?
                );
            }
        } else {
            return Err(anyhow!("Failed to parse {}.", kv))
        }
    }
    Ok(parsed)
}

fn make_response_body(map: HashMap<&str, &str>) -> String {
    map.into_iter()
        .map(|(k, v)| format!("{}={}", k, base64_encode(v)))
        .collect::<Vec<String>>()
        .join("&")
}

async fn gs_register_respond(_req: Request<Body>, user: Option<&UserInfo>, mut session_backend: RwLockWriteGuard<'_, SessionsBackend>) -> Response<Body> {
    let mut response_map = HashMap::new();
    // challenge - A random 8-character challenge string (upper-case ASCII only) to be used as the password when logging in to GameSpy for this session
    // locator - Usage unknown. Always gamespy.com
    // retry - Probably a flag to retry creating the account due to an error. In practice, this is always 0, presumably signifying that no retry was needed. If the request data is incorrect (e.g. if the password doesn't match Nintendo's records), this value will be 1 and only returncd and datetime will be included in the response.
    // returncd - Probably a return code to signify success or failure. In practice, this is always 001, presumably signifying success. It is possible to get a value 109 if there was an error in interpreting the request (e.g. if the password presumably doesnt match the username) but the exact meaning of this code is unknown. In this case, retry will be 1 and all other fields except datetime will be missing.
    // token - An authentication token to present to the GameSpy servers as the username for this session. Appears to be a random string of 96 bytes, which is then base64-encoded and prefixed by "NDS"
    // datetime - The time of the server in GMT, as if formatted using the Unicode date format pattern "yyyyMMddHHmmss" (e.g. 20140312053512 for ISO date "2014-03-12T05:35:12")
    match user {
        // Error
        None => {
            debug!("Error during registration: Sending reponse.");
            response_map.insert("retry", "1");
            response_map.insert("returncd", "109");
        }
        // Success
        Some(u) => {
            let session = session_backend.new_for(u).await;
            debug!("Success during registration: Sending session: {:?}", session);
            response_map.insert("retry", "0");
            response_map.insert("returncd", "001");
            response_map.insert("challenge", &session.challenge);
            response_map.insert("locator", "gamespy.com");
            response_map.insert("token", &session.token);
        }
    }
    let date = Utc::now().format("%Y%m%d%H%M%S").to_string();
    response_map.insert("datetime", &date);
    Response::builder()
        .header("Content-type", "text/plain")
        .header("Server", concatcp!("Wingull Flight Center ", VERSION))
        .body(Body::from(make_response_body(response_map)))
        .unwrap_or_default() // not ideal but what you gonna do.
}

async fn gs_register(mut req: Request<Body>, backends: BackendsRef) -> Result<Response<Body>, hyper::Error> {
    debug!("Client tries to register.");
    match parse_request_body(&mut req).await {
        Ok(request_data) => {
            let bwrite = backends.write().await;
            match bwrite.users.write().await.create_or_loadfrom_hashmap(request_data, bwrite.games.read().await).await {
                Ok(user) => {
                    return Ok(gs_register_respond(req, Some(user), bwrite.sessions.write().await).await)
                },
                Err(e) => warn!("GS /ac: Failed to register a user. Error: {} -- {}", e, e.backtrace())
            };
        }
        Err(e) => warn!("GS /ac: Client sent invalid data during registration, ghosting. Error: {} -- {}", e, e.backtrace())
    }
    Ok(gs_register_respond(req, None, backends.write().await.sessions.write().await).await)
}

async fn svc_http_service(req: Request<Body>, backends: BackendsRef) -> Result<Response<Body>, hyper::Error> {
    let (host, method, path) = (extract_host(&req), req.method(), req.uri().path());
    debug!("HTTP request: {:?}", (&host, method, path));
    match (host.as_str(), method, path) {
        (crate::dns::DN_CONNTEST, &Method::GET, "/") => Ok(Response::new(Body::from(
            "OK",
        ))),

        (crate::dns::DN_NAS, &Method::POST, "/ac") => gs_register(req, backends).await,

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

pub async fn run_http<'a>(http_port: u16/*, https_port: u16, cert: Identity*/, backends: BackendsRef) -> Result<(), anyhow::Error> {
    let http_addr = SocketAddr::from(([0, 0, 0, 0], http_port));
    /*let https_addr = SocketAddr::from(([0, 0, 0, 0], https_port));

    let mut builder = native_tls::TlsAcceptor::builder(cert);
    builder.min_protocol_version(Some(Protocol::Sslv3));
    builder.max_protocol_version(Some(Protocol::Tlsv12));
    let tls_acceptor = TlsAcceptor::from(builder.build()?);
    let tcp_https = TcpListener::bind(&https_addr).await?;
    let incoming_tls_stream: AsyncStream<Result<TlsStream<TcpStream>, io::Error>, _> = stream! {
        loop {
            let (socket, _) = tcp_https.accept().await?;
             match tls_acceptor.accept(socket).await {
                Ok(v) => yield Ok(v),
                Err(e) => {
                    warn!("TLS accept error! {:?}", e);
                    //Err(e)
                }
            }
        }
    };
    let acceptor = accept::from_stream(incoming_tls_stream);

    let server_https = Server::builder(acceptor).serve(make_service_fn(|_| async { Ok::<_, hyper::Error>(service_fn(svc_http_service)) }));*/
    // rust sure is beautiful sometimes:
    let server_http = Server::bind(&http_addr)
        .serve(make_service_fn(move |_| {
            let ibackends = backends.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    let iibackends = ibackends.clone();
                    svc_http_service(req, iibackends)
                }))
            }
        }));
    info!("HTTP server running on TCP {}", http_port);/* / https {}", http_port, https_port);*/
    //try_join!(server_http, server_https)?;
    Ok(server_http.await?)
}
