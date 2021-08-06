use anyhow::Result;
use bytes::Bytes;
use chrono::Utc;
use chrono::{Duration, TimeZone};
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509Builder, X509Name, X509NameBuilder, X509};
use std::fs::File;
use std::io::Write;
use std::ops::{Add, Shr, Sub};
use std::time::Duration as StdDuration;

pub const CA_CRT_CHIA: &str = include_str!("../../chia-original/chia/ssl/chia_ca.crt");
pub const CA_CRT_MOZILLA: &str = include_str!("../../chia-original/mozilla-ca/cacert.pem");
pub const CA_KEY_CHIA: &str = include_str!("../../chia-original/chia/ssl/chia_ca.key");
pub const CERT_COMMON_NAME: &str = "Chia";
pub const CERT_DNS_NAME: &str = "chia.net";
pub const CERT_ORGANIZATION_NAME: &str = "Chia";
pub const CERT_ORGANIZATION_UNIT_NAME: &str = "Organic Farming Division";
pub const CERT_VALIDITY_DAY: u32 = 2;
pub const CERT_VALIDITY_MONTH: u32 = 8;
pub const CERT_VALIDITY_YEAR: i32 = 2100;
pub const DUR_ONE_DAY: StdDuration = StdDuration::from_secs(24 * 60 * 60);
pub const DUR_TEN_YEARS: StdDuration = StdDuration::from_secs(10 * 365 * 24 * 60 * 60);
pub const RSA_BIT_SIZE: u32 = 2048;

fn get_random_big_number() -> Result<Asn1Integer> {
    let mut random_numbers = [0u8; 20];
    rand_bytes(&mut random_numbers)?;
    let random_numbers = BigNum::from_slice(&random_numbers)?;
    let random_numbers = random_numbers.shr(1);

    Ok(Asn1Integer::from_bn(&random_numbers)?)
}

fn get_cert_subject() -> Result<X509Name> {
    let mut new_subject = X509NameBuilder::new()?;
    new_subject.append_entry_by_nid(Nid::COMMONNAME, CERT_COMMON_NAME)?;
    new_subject.append_entry_by_nid(Nid::ORGANIZATIONNAME, CERT_ORGANIZATION_NAME)?;
    new_subject.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, CERT_ORGANIZATION_UNIT_NAME)?;

    Ok(new_subject.build())
}

pub fn generate_ca_signed_cert(
    ca_cert: &Bytes,
    ca_key: &Bytes,
    cert_out_file: &mut File,
    key_out_file: &mut File,
) -> Result<()> {
    let oneday = Duration::from_std(DUR_ONE_DAY)?;
    let root_cert = X509::from_pem(ca_cert)?;
    let root_key = PKey::private_key_from_pem(ca_key)?;
    let cert_key = Rsa::generate(RSA_BIT_SIZE)?;
    let cert_key_public = PKey::from_rsa(Rsa::from_public_components(
        cert_key.n().to_owned()?,
        cert_key.e().to_owned()?,
    )?)?;
    let new_subject = get_cert_subject()?;
    let random_numbers = get_random_big_number()?;
    let not_before = Utc::today().sub(oneday).and_hms(0, 0, 0);
    let not_before = Asn1Time::from_unix(not_before.timestamp())?;
    let not_after = Utc
        .ymd(CERT_VALIDITY_YEAR, CERT_VALIDITY_MONTH, CERT_VALIDITY_DAY)
        .and_hms(0, 0, 0);
    let not_after = Asn1Time::from_unix(not_after.timestamp())?;
    let mut cert = X509Builder::new()?;
    let context = cert.x509v3_context(Some(&root_cert), None);
    let cert_extension = SubjectAlternativeName::new()
        .dns(CERT_DNS_NAME)
        .build(&context)?;
    cert.set_subject_name(&new_subject)?;
    cert.set_issuer_name(root_cert.issuer_name())?;
    cert.set_pubkey(&cert_key_public)?;
    cert.set_serial_number(&random_numbers)?;
    cert.set_not_before(&not_before)?;
    cert.set_not_after(&not_after)?;
    cert.append_extension(cert_extension)?;
    cert.sign(&root_key, MessageDigest::sha256())?;
    let cert = cert.build();
    let cert_pem = cert.to_pem()?;
    let key_pem = cert_key.private_key_to_pem()?;
    cert_out_file.write_all(&cert_pem)?;
    key_out_file.write_all(&key_pem)?;

    Ok(())
}

pub fn make_ca_cert(cert_out_file: &mut File, key_out_file: &mut File) -> Result<()> {
    let tenyears = Duration::from_std(DUR_TEN_YEARS)?;
    let root_key_rsa = Rsa::generate(RSA_BIT_SIZE)?;
    let root_key_public = PKey::from_rsa(Rsa::from_public_components(
        root_key_rsa.n().to_owned()?,
        root_key_rsa.e().to_owned()?,
    )?)?;
    let root_key = PKey::from_rsa(root_key_rsa.clone())?;
    let new_subject = get_cert_subject()?;
    let random_numbers = get_random_big_number()?;
    let not_before = Utc::now();
    let not_before = Asn1Time::from_unix(not_before.timestamp())?;
    let not_after = Utc::now().add(tenyears);
    let not_after = Asn1Time::from_unix(not_after.timestamp())?;
    let cert_extension = BasicConstraints::new().ca().critical().build()?;
    let mut root_cert = X509Builder::new()?;
    root_cert.set_subject_name(&new_subject)?;
    root_cert.set_issuer_name(&new_subject)?;
    root_cert.set_pubkey(&root_key_public)?;
    root_cert.set_serial_number(&random_numbers)?;
    root_cert.set_not_before(&not_before)?;
    root_cert.set_not_after(&not_after)?;
    root_cert.append_extension(cert_extension)?;
    root_cert.sign(&root_key, MessageDigest::sha256())?;
    let root_cert = root_cert.build();
    let root_cert_pem = root_cert.to_pem()?;
    let root_key_pem = root_key_rsa.private_key_to_pem()?;
    cert_out_file.write_all(&root_cert_pem)?;
    key_out_file.write_all(&root_key_pem)?;

    Ok(())
}
