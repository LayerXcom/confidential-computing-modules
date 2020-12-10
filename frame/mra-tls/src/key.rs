use anyhow::Result;
use sgx_tcrypto::SgxEccHandle;
use sgx_types::{sgx_ec256_private_t, sgx_ec256_public_t};
use std::vec::Vec;
use yasna::models::ObjectIdentifier;
use yasna::{construct_der, Tag};
use bit_vec::BitVec;

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
                        writer.next().write_tagged(Tag::context(1), |writer| { // Writes a (explicitly) tagged value.
                            writer.write_bitvec(&BitVec::from_bytes(&pub_key_bytes)); // Writes BitVec as an ASN.1 BITSTRING value.
                        });
                    });
                });
                writer.next().write_bytes(&inner_key_der);
            });
        })
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
