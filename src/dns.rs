use std::collections::BTreeMap;
use std::future;
use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::str::FromStr;
use std::time::Duration;
use std::sync::{Arc, RwLock};
use anyhow::{anyhow, Error};
use const_format::concatcp;
use log::{debug, error, info};
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_server::authority::{AuthLookup, Authority, AuthorityObject, LookupError, MessageRequest, UpdateResult, ZoneType};
use trust_dns_server::client::op::LowerQuery;
use trust_dns_server::client::proto::rr::RecordType;
use trust_dns_server::client::rr::{LowerName, Name, RrKey};
use trust_dns_server::client::rr::dnssec::SupportedAlgorithms;
use trust_dns_server::proto::rr::rdata::SOA;
use trust_dns_server::proto::rr::{RData, RecordSet};
use trust_dns_server::proto::rr::Record;
use trust_dns_server::store::in_memory::InMemoryAuthority;

//const MASTER_DOMAIN: &'static str = "nintendowifi.net";
const MASTER_DOMAIN: &str = "wc.skytemple.org";

pub(crate) const DN_CONNTEST: &str = concatcp!("conntest.", MASTER_DOMAIN);
pub(crate) const DN_NAS: &str = concatcp!("nas.", MASTER_DOMAIN);
pub(crate) const DN_GAMESTATS: &str = concatcp!("gamestats2.gs.", MASTER_DOMAIN);
const DNS_NAMES: [&str; 7] = [
    MASTER_DOMAIN,
    DN_NAS,
    concatcp!("gs.", MASTER_DOMAIN),
    DN_CONNTEST,
    concatcp!("pokedungeonds.available.gs.", MASTER_DOMAIN),
    concatcp!("pokedungeonds.master.gs.", MASTER_DOMAIN),
    concatcp!("*.gs.", MASTER_DOMAIN),
];

struct LoggedAuthority(InMemoryAuthority);

impl LoggedAuthority {
    pub fn new(
        origin: Name,
        records: BTreeMap<RrKey, RecordSet>,
        zone_type: ZoneType,
        allow_axfr: bool,
    ) -> Result<Self, String> {
        Ok(Self(InMemoryAuthority::new(origin, records, zone_type, allow_axfr)?))
    }
}

impl Authority for LoggedAuthority {
    type Lookup = AuthLookup;
    type LookupFuture = future::Ready<Result<Self::Lookup, LookupError>>;

    fn zone_type(&self) -> ZoneType {
        self.0.zone_type()
    }

    fn is_axfr_allowed(&self) -> bool {
        self.0.is_axfr_allowed()
    }

    fn update(&mut self, update: &MessageRequest) -> UpdateResult<bool> {
        self.0.update(update)
    }

    fn origin(&self) -> &LowerName {
        self.0.origin()
    }

    fn lookup(&self, name: &LowerName, rtype: RecordType, is_secure: bool, supported_algorithms: SupportedAlgorithms) -> Pin<Box<dyn Future<Output=Result<Self::Lookup, LookupError>> + Send>> {
        debug!("DNS lookup: {:?} {:?}", rtype, name.to_string());
        self.0.lookup(name, rtype, is_secure, supported_algorithms)
    }

    fn search(&self, query: &LowerQuery, is_secure: bool, supported_algorithms: SupportedAlgorithms) -> Pin<Box<dyn Future<Output=Result<Self::Lookup, LookupError>> + Send>> {
        debug!("DNS search: {:?}", query.to_string());
        self.0.search(query, is_secure, supported_algorithms)
    }

    fn get_nsec_records(&self, name: &LowerName, is_secure: bool, supported_algorithms: SupportedAlgorithms) -> Pin<Box<dyn Future<Output=Result<Self::Lookup, LookupError>> + Send>> {
        self.0.get_nsec_records(name, is_secure, supported_algorithms)
    }
}

pub async fn run_dns(dns_port: u16, dns_ip: Ipv4Addr) -> Result<(), Error> {
    let mut catalog = trust_dns_server::authority::Catalog::new();
    let mut records = BTreeMap::new();

    // SOA data
    let mut record_set = RecordSet::new(&Name::from_str(".")?, RecordType::SOA, 0);
    let rdata = RData::SOA(SOA::new(Name::from_str(".")?, Name::from_str(".")?, 0, 86400, 7200, 3600000, 3600));
    record_set.insert(Record::from_rdata(Name::from_str(".")?, 3600, rdata), 0);
    records.insert(RrKey::new(LowerName::from_str(".")?, RecordType::SOA), record_set);

    for (i, domain) in DNS_NAMES.into_iter().enumerate() {
        let mut record_set = RecordSet::new(&Name::from_str(domain)?, RecordType::A, (i + 1) as u32);
        let rdata = RData::A(dns_ip);
        record_set.insert(Record::from_rdata(Name::from_str(domain)?, 3600, rdata), (i + 1) as u32);
        records.insert(RrKey::new(LowerName::from_str(domain)?, RecordType::A), record_set);
    }

    let authority = LoggedAuthority::new(
        Name::from_str(".")?,
        records,
        ZoneType::Primary,
        false
    ).map_err(|x| anyhow!(x))?;
    catalog.upsert(
        LowerName::from_str(".")?,
        Box::new(Arc::new(RwLock::new(authority))) as Box<dyn AuthorityObject>
    );

    let mut server = trust_dns_server::ServerFuture::new(catalog);
    let bind = format!("0.0.0.0:{}", dns_port);
    let listener = TcpListener::bind(&bind).await?;
    let socket = UdpSocket::bind(&bind).await?;
    server.register_listener(listener, Duration::from_secs(5));
    server.register_socket(socket);


    info!("DNS server running on TCP/UDP {}", dns_port);
    match server.block_until_done().await {
        Ok(()) => {
            info!("DNS server stopped.");
        },
        Err(e) => {
            let error_msg = format!(
                "DNS server has encountered an error: {}",
                e
            );

            error!("{}", error_msg);
            panic!("{}", error_msg);
        }
    }
    Ok(())
}
