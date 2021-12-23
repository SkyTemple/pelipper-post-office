#![feature(async_closure)]

#[cfg(feature = "dns")]
mod dns;
//mod cert;
mod http;
mod config;
mod gs_tcp;
mod gs_udp;
mod util;
mod backend;

use std::net::Ipv4Addr;
use std::sync::Arc;
use anyhow::Error;
use log::{info, warn};
use structopt::StructOpt;
use futures::future::select_all;
use tokio::sync::RwLock;
use crate::backend::backends::Backends;
//use crate::cert::get_cert;
use crate::dns::run_dns;
use crate::gs_tcp::run_gs_tcp;
use crate::gs_udp::run_gs_udp;
use crate::http::run_http;

#[derive(StructOpt, Debug)]
#[structopt()]
struct Opt {
    /// Silence all output
    #[structopt(short = "q")]
    quiet: bool,
    /// Verbose mode (-v)
    #[structopt(short = "v")]
    verbose: bool,
    /// Port the HTTP server will listen on.
    #[structopt(short = "p", long = "http-port", default_value = "80")]
    http_port: u16,
    /*/// Port the HTTPS server will listen on.
    #[structopt(short = "s", long = "https-port", default_value = "443")]
    https_port: u16,*/
    /// Port the DNS server will listen on.
    #[cfg(feature = "dns")]
    #[structopt(short = "d", long = "dns-port", default_value = "53")]
    dns_port: u16,
    /// Port the GS UDP server will listen on.
    #[structopt(short = "u", long = "gs-udp-port", default_value = "27900")]
    gs_udp_port: u16,
    /// Port the GS TCP server will listen on.
    #[structopt(short = "t", long = "gs-tcp-port", default_value = "29900")]
    gs_tcp_port: u16,
    /// External IP address the server is listening at (for DNS)
    #[cfg(feature = "dns")]
    #[structopt(short = "i", long = "dns-ip", default_value = "127.0.0.1")]
    dns_ip: Ipv4Addr,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let opt = Opt::from_args();

    stderrlog::new()
        .module(module_path!())
        .quiet(opt.quiet)
        .verbosity(if opt.verbose {3} else {2})
        .timestamp(stderrlog::Timestamp::Millisecond)
        .init()?;

    info!("wingull-flight-center is starting...");

    let backends_ref = Arc::new(RwLock::new(Backends::new()));
    let mut servers = vec![];

    // Initialize certificates
    /*let cert = get_cert()?;*/

    // dns
    #[cfg(feature = "dns")]
    servers.push(tokio::spawn(async move {
        run_dns(opt.dns_port, opt.dns_ip).await
    }));

    // http
    let br = backends_ref.clone();
    servers.push(tokio::spawn(async move {
        run_http(opt.http_port/*, opt.https_port, cert*/, br).await
    }));

    // udp
    let br = backends_ref.clone();
    servers.push(tokio::spawn(async move {
        run_gs_udp(opt.gs_udp_port, br).await
    }));

    // tcp
    let br = backends_ref.clone();
    servers.push(tokio::spawn(async move {
        run_gs_tcp(opt.gs_tcp_port, br).await
    }));

    let (result, _, _) = select_all(servers).await;
    warn!("One of the components stopped. Exiting...");
    result??;
    Ok(())
}
