use crate::asn1_seq;
use crate::cert::{Asn1Ty, CertSignAlgo, TbsCert};
use anyhow::Result;
use bit_vec::BitVec;
use chrono::TimeZone;
use num_bigint::BigUint;
use sgx_tcrypto::SgxEccHandle;
use sgx_types::{sgx_ec256_private_t, sgx_ec256_public_t, sgx_report_data_t};
use std::borrow::ToOwned;
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec::Vec;
use yasna::models::{ObjectIdentifier, UTCTime};
use yasna::{construct_der, Tag};

/// Validation days of a certification for TLS connection
const CERT_VALID_DAYS: i64 = 30;

pub struct NistP256KeyPair {
    priv_key: sgx_ec256_private_t,
    pub_key: sgx_ec256_public_t,
}

impl NistP256KeyPair {
    pub fn new() -> Result<Self> {
        let ecc_handle = SgxEccHandle::new();
        ecc_handle.open()?;
        let (priv_key, pub_key) = ecc_handle.create_key_pair()?;
        ecc_handle.close()?;
        Ok(Self { priv_key, pub_key })
    }

    /// DER-encoded ASN.1 in either PKCS#8 format.
    pub fn priv_key_into_der(&self) -> Vec<u8> {
        // http://oid-info.com/get/1.2.840.10045.2.1
        let ec_pub_key_oid = ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]);
        // http://oid-info.com/get/1.2.840.10045.3.1.7
        let prime256v1_oid = ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]);

        let pub_key_bytes = self.pub_key_into_bytes();
        let priv_key_bytes = self.priv_key_into_bytes();

        // Constructs DER-encoded data as Vec<u8>
        construct_der(|writer| {
            writer.write_sequence(|writer| {
                // Writes ASN.1 SEQUENCE.
                writer.next().write_u8(0); // Writes u8 as an ASN.1 INTEGER value.
                writer.next().write_sequence(|writer| {
                    writer.next().write_oid(&ec_pub_key_oid); // Writes an ASN.1 object identifier.
                    writer.next().write_oid(&prime256v1_oid);
                });

                let inner_key_der = construct_der(|writer| {
                    writer.write_sequence(|writer| {
                        writer.next().write_u8(1);
                        writer.next().write_bytes(&priv_key_bytes); // Writes &[u8] as an ASN.1 OCTETSTRING value.
                        writer.next().write_tagged(Tag::context(1), |writer| {
                            // Writes a (explicitly) tagged value.
                            writer.write_bitvec(&BitVec::from_bytes(&pub_key_bytes));
                            // Writes BitVec as an ASN.1 BITSTRING value.
                        });
                    });
                });
                writer.next().write_bytes(&inner_key_der);
            });
        })
    }

    /// Creating a self-signed X.509 v3 certificate with remote attestation report as extensions
    /// reference: https://tools.ietf.org/html/rfc5280#section-4.1.2.1
    pub fn create_cert_with_extension(
        &self,
        issuer: &str,
        subject: &str,
        payload: &[u8],
    ) -> Vec<u8> {
        // http://oid-info.com/get/1.2.840.10045.4.3.2
        let ecdsa_with_sha256_oid = ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 3, 2]);
        // http://oid-info.com/get/2.5.4.3
        let common_name_oid = ObjectIdentifier::from_slice(&[2, 5, 4, 3]);
        // http://oid-info.com/get/1.2.840.10045.2.1
        let ec_public_key_oid = ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]);
        // http://oid-info.com/get/1.2.840.10045.3.1.7
        let prime256v1_oid = ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]);
        // http://oid-info.com/get/2.16.840.1.113730.1.13
        let comment_oid = ObjectIdentifier::from_slice(&[2, 16, 840, 1, 113_730, 1, 13]);

        let pub_key_bytes = self.pub_key_into_bytes();

        // current time must not be later than UNIX_EPOCH
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let issue_ts = chrono::Utc.timestamp(now.as_secs() as i64, 0);

        // CERT_VALID_DAYS must not be less than zero
        let expire = now + chrono::Duration::days(CERT_VALID_DAYS).to_std().unwrap();
        let expire_ts = chrono::Utc.timestamp(expire.as_secs() as i64, 0);

        let tbs_cert_der = construct_der(|writer| {
            // When extensions are used, as expected in this profile, version MUST be 3 (value is 2)
            let version: i8 = 2;
            // must be positive integer and unique for each certificate issued by a given CA
            let serial: u8 = 1;
            // the algorithm identifier for the algorithm used by the CA to sign the certificate
            let cert_sign_algo = asn1_seq!(ecdsa_with_sha256_oid.clone());
            //  the entity that has signed and issued the certificate
            let issuer = asn1_seq!(asn1_seq!(asn1_seq!(
                common_name_oid.clone(),
                issuer.to_owned(),
            )));
            // the time interval during which the CA warrants that it will maintain information about the status of the certificate
            let valid_range = asn1_seq!(
                UTCTime::from_datetime(&issue_ts),
                UTCTime::from_datetime(&expire_ts),
            );
            // the entity associated with the public key stored in the subject public key field
            let subject = asn1_seq!(asn1_seq!(asn1_seq!(
                common_name_oid.clone(),
                subject.to_owned(),
            )));
            // the public key and identify the algorithm with which the key is used
            let pub_key = asn1_seq!(
                asn1_seq!(ec_public_key_oid, prime256v1_oid,),
                BitVec::from_bytes(&pub_key_bytes),
            );
            let sgx_ra_cert_ext = asn1_seq!(asn1_seq!(comment_oid, payload.to_owned()));
            let tbs_cert = asn1_seq!(
                version,
                serial,
                cert_sign_algo,
                issuer,
                valid_range,
                subject,
                pub_key,
                sgx_ra_cert_ext,
            );
            TbsCert::dump(writer, tbs_cert);
        });

        // must be panic if handling ecc fails
        let ecc_handle = SgxEccHandle::new();
        ecc_handle.open().unwrap();
        let sig = ecc_handle
            .ecdsa_sign_slice(&tbs_cert_der.as_slice(), &self.priv_key)
            .unwrap();
        ecc_handle.close().unwrap();

        let sig_der = construct_der(|writer| {
            writer.write_sequence(|writer| {
                let mut sig_x = sig.x;
                sig_x.reverse();
                let mut sig_y = sig.y;
                sig_y.reverse();
                writer.next().write_biguint(&BigUint::from_slice(&sig_x)); // Writes BigUint as an ASN.1 INTEGER value
                writer.next().write_biguint(&BigUint::from_slice(&sig_y));
            });
        });

        // Certificate  ::=  SEQUENCE  {
        // tbsCertificate       TBSCertificate,
        // signatureAlgorithm   AlgorithmIdentifier,
        // signatureValue       BIT STRING  }
        construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_der(&tbs_cert_der.as_slice());
                CertSignAlgo::dump(writer.next(), asn1_seq!(ecdsa_with_sha256_oid.clone()));
                writer
                    .next()
                    .write_bitvec(&BitVec::from_bytes(&sig_der.as_slice()));
            });
        })
    }

    pub fn report_data(&self) -> sgx_report_data_t {
        let mut report_data = sgx_report_data_t::default();
        let mut pub_key_gx = self.pub_key.gx;
        pub_key_gx.reverse();
        let mut pub_key_gy = self.pub_key.gy;
        pub_key_gy.reverse();
        report_data.d[..32].copy_from_slice(&pub_key_gx);
        report_data.d[32..].copy_from_slice(&pub_key_gy);

        report_data
    }

    /// The Standards of Efficient Cryptography (SEC) encoding is used to serialize ECDSA public keys.
    /// We use uncompressed format.
    /// Uncompressed:
    /// - 0x04 byte: header byte to indicate ECDSA point
    /// - the x coordinate as a 32-byte big-endian integer
    /// - the y coordinate as a 32-byte big-endian integer
    /// For more details: https://secg.org/sec1-v2.pdf#subsubsection.2.3.3, https://bitcoin.stackexchange.com/questions/92680/what-are-the-der-signature-and-sec-format
    fn pub_key_into_bytes(&self) -> Vec<u8> {
        let mut pub_key_bytes: Vec<u8> = vec![4];
        pub_key_bytes.extend(self.pub_key.gx.iter().rev());
        pub_key_bytes.extend(self.pub_key.gy.iter().rev());
        pub_key_bytes
    }

    fn priv_key_into_bytes(&self) -> Vec<u8> {
        let mut priv_key_bytes: Vec<u8> = vec![];
        priv_key_bytes.extend(self.priv_key.r.iter().rev());
        priv_key_bytes
    }
}
