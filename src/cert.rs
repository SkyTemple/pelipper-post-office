use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::ops::Add;
use std::path::PathBuf;
use anyhow::{anyhow, Error};
use chrono::{DateTime, Duration, Utc};
use directories::ProjectDirs;
use log::info;
use tokio_native_tls::native_tls::Identity;
use crate::config::config_dir;

/// TODO: Does not support 1024bit RSA key generation yet
/*
pub(crate) fn create_cert() -> Result<TlsCert, Error> {
    let mut params = CertificateParams::new(
        vec!["test.example".to_string()]
    );
    params.alg = &PKCS_RSA_SHA256;
    params.not_before = Utc::now();
    params.not_after = params.not_before + Duration::days(2000);
    let mut dn = DistinguishedName::new();
    dn.push(CountryName, "DE");
    dn.push(StateOrProvinceName, "NA");
    dn.push(OrganizationName, "Capypara");
    dn.push(OrganizationalUnitName, "SkyTemple");
    dn.push(CommonName, "SkyTemple");
    params.distinguished_name = dn;
    let cert = Certificate::from_params(params)?;
    let config_dir = config_dir()?;
    let private_key = cert.serialize_private_key_der();
    let key_path = config_dir.join("tls.key");
    let cert_path = config_dir.join("tls.crt");
    let pubkey_path = config_dir.join("tls.pub");
    let pubkey_der = cert.get_key_pair().public_key_der();
    let pubkey_path_nds = config_dir.join("tls_nds_pub.bin");
    fs::write(&key_path, &private_key)?;
    fs::write(&cert_path, cert.serialize_der()?)?;
    fs::write(&pubkey_path, &pubkey_der)?;
    // TODO: I sure hope this never changes :) - parse ASN???????
    fs::write(
        &pubkey_path_nds,
        (&pubkey_der[23..23+66])
            .iter()
            .chain([0; 62].iter())
            .copied()
            .collect::<Vec<u8>>()
    )?;
    Ok(TlsCert {
        cert, key: PrivateKey(private_key)
    })
}
*/

// openssl req -x509 -sha256 -nodes -days 3650 -newkey rsa:1024 -keyout tls.pem.key -out ctls.der.crt
// openssl x509 -pubkey -noout -in tls.der.crt -inform DER > tls.der.pub (and then see https://crypto.stackexchange.com/questions/18031/how-to-find-modulus-from-a-rsa-public-key for 128 byte key extraction)
// openssl pkcs12 -export -out identity.pfx -inkey key.pem -in cert.pem -certfile chain_certs.pem
// pw skytemple
pub(crate) fn get_cert() -> Result<Identity, Error> {
    // todo: error handling if doesn't exist
    let config_dir = config_dir()?;
    let key_path = config_dir.join("tls.pfx");
    Ok(Identity::from_pkcs12(&*fs::read(key_path)?, "skytemple")?)
}
