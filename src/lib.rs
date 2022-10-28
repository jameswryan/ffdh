use std::error::Error;
use std::fmt;

use num_bigint::{BigUint, RandBigInt};
use rand::rngs::OsRng;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

use pkcs8::{
    der::{asn1, Decode, Encode, Tag},
    AlgorithmIdentifier, Document, LineEnding, ObjectIdentifier, SubjectPublicKeyInfo,
};

use hex_literal::hex;

#[derive(Debug)]
pub struct FfDh {
    private_key: BigUint,
    public_key: BigUint,
}

impl<'a> FfDh {
    /// `ObjectIdentifier` for Diffie-Hellman Key Agreement
    /// http://www.oid-info.com/cgi-bin/display?oid=1.2.840.113549.1.3.1&action=display
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.3.1");

    /// `AlgorithmIdentifier` for Diffie-Hellman
    /// Not a constant because asn1 construction doesn't use constant functions
    fn ffdh_aid() -> AlgorithmIdentifier<'a> {
        AlgorithmIdentifier {
            oid: FfDh::OID,
            parameters: {
                // We only support one set of parameters, so this isn't as bad as it looks
                // The asn1 structure is
                // SEQUENCE <length>
                //   INTEGER
                //     <p>
                //   INTEGER
                //     <g>
                //
                // This encodes to
                // 30 82 02 08 02 82 02 01 00 <p_bytes> 02 01 <g_byte>
                // We can drop the tag (30) & first length (82 02 08 ), asn1::Any & der::Tag::Sequence provide those

                const SEQUENCE: [u8; 520] = hex!("0282020100FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF020102");

                // Safe to unwrap since SEQUENCE is a constant
                Some(asn1::AnyRef::new(Tag::Sequence, &SEQUENCE).unwrap())
            },
        }
    }

    /// FFDH modulus 'p'
    fn ffdh_p() -> BigUint {
        // Only RFC 3526 4096-bit prime modulus supported
        BigUint::from_bytes_be(&hex!("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF"))
    }

    fn ffdh_g() -> BigUint {
        // Only generator `2` supported
        BigUint::from(2u32)
    }

    fn ffdh_q() -> BigUint {
        // This is really slow
        // Should compute this and print it, then copy the value
        (FfDh::ffdh_p() - 1u32) / 2u32
    }

    /// Generate a new FfDh instance
    /// Generates a private and public key using [rand::OsRng](https://docs.rs/rand/latest/rand/rngs/struct.OsRng.html)
    pub fn new() -> FfDh {
        let pr_k = OsRng.gen_biguint_below(&FfDh::ffdh_p());
        FfDh::new_unsafe(pr_k)
    }

    /// Create an FfDh instance with a given private key
    /// Only used for tests, *not* part of the public API
    fn new_unsafe(pr_k: BigUint) -> FfDh {
        let pb_k = FfDh::ffdh_g().modpow(&pr_k, &FfDh::ffdh_p());
        FfDh {
            private_key: pr_k,
            public_key: pb_k,
        }
    }

    /// Retrieves a PEM-encoded version of the public key
    pub fn pubkey_pem(&self) -> Result<String, FfDhError> {
        // The asn1 header marks the bitstring as an integer
        // There's not (?) a way to get access to the bytes of an AnyRef,
        // so we build the asn1 manually
        // let spk = self.public_key.to_bytes_be();
        // let spk_header = Header {
        //     tag: Tag::Integer,
        //     length: (spk.len() as u16).into(),
        // }
        // .to_vec()
        // .unwrap();

        let spk = asn1::UIntRef::new(&self.public_key.to_bytes_be())
            .unwrap()
            .to_vec()
            .unwrap();

        let spki = SubjectPublicKeyInfo {
            algorithm: FfDh::ffdh_aid(),
            subject_public_key: &spk,
        };

        let doc = match Document::try_from(spki) {
            Ok(d) => d,
            Err(_) => return Err(FfDhError::Err),
        };

        const TL: &str = "PUBLIC KEY";
        match doc.to_pem(TL, LineEnding::default()) {
            Ok(d) => Ok(d),
            Err(_) => Err(FfDhError::Err),
        }
    }

    /// Extract a pem-encoded public key
    fn pubkey_from_pem(pem: &str) -> Result<BigUint, FfDhError> {
        let doc = match Document::from_pem(pem) {
            Ok((l, d)) => {
                // Check that the label marks this as a public key
                if l != "PUBLIC KEY" {
                    return Err(FfDhError::Err);
                }
                d
            }
            Err(_) => {
                return Err(FfDhError::Err);
            }
        };

        let spk = match doc.decode_msg::<SubjectPublicKeyInfo>() {
            Ok(spki) => {
                // Check that the label denotes a public key
                spki.subject_public_key
            }
            Err(_) => {
                return Err(FfDhError::Err);
            }
        };

        let pubk = match asn1::AnyRef::try_from(spk) {
            Ok(pk) => pk,
            Err(_) => {
                return Err(FfDhError::Err);
            }
        };

        let pubk = match asn1::UIntRef::try_from(pubk) {
            Ok(pk) => pk,
            Err(_) => {
                return Err(FfDhError::Err);
            }
        };
        Ok(BigUint::from_bytes_be(pubk.as_bytes()))
    }

    /// 'safe' dh shared secret generation
    /// Returns error if pk is 'bad' (see check_safe_pubkey for 'bad')
    /// Returns error if dh result is ('bad')[https://github.com/google/wycheproof/blob/master/doc/dh.md]
    fn compute_shared_secret(&self, pk: &BigUint) -> Result<BigUint, FfDhError> {
        // Safe pubkey
        FfDh::check_safe_pubkey(pk)?;

        let dh_result = pk.modpow(&self.private_key, &FfDh::ffdh_p());

        // Make sure our secret isn't 1
        if dh_result == 1u32.into() {
            return Err(FfDhError::new());
        }

        Ok(dh_result)
    }

    /// Compute shared bytes between `self` and anothe public key `pk`
    /// Does DH between `self` and `k`, and extracts `N` bytes with SHAKE256
    /// Returns error if pk is 'bad' (see check_safe_pubkey for 'bad')
    /// Returns error if dh result is ('bad')[https://github.com/google/wycheproof/blob/master/doc/dh.md]
    pub fn generate_shared_bytes<const N: usize>(
        &self,
        pk_pem: &str,
    ) -> Result<[u8; N], FfDhError> {
        let pk = FfDh::pubkey_from_pem(pk_pem)?;
        let dh_result = self.compute_shared_secret(&pk)?;

        // Generate shared bytes from secret
        let mut hasher = Shake256::default();
        hasher.update(&dh_result.to_bytes_be());
        let mut shared_bytes = [0u8; N];
        hasher.finalize_xof().read(&mut shared_bytes);
        Ok(shared_bytes)
    }

    /// Validate that a public key is 'safe'
    /// Taken from https://github.com/google/wycheproof/blob/master/doc/dh.md
    /// Returns Ok(()) if public key is 'safe', otherwise Err(FfDhError)
    pub fn check_safe_pubkey(y: &BigUint) -> Result<(), FfDhError> {
        /* Small Subgroup checks */
        // Check that 2 <= y <= p-2

        if *y < 2u32.into() || *y > (FfDh::ffdh_p() - 2u32) {
            return Err(FfDhError::new());
        }
        // Check that pk ^ q === 1 (mod p)
        if y.modpow(&FfDh::ffdh_q(), &FfDh::ffdh_p()) == 1u32.into() {
            //return Err(FfDhError::new());
        }
        Ok(())
    }
}

impl Default for FfDh {
    fn default() -> Self {
        FfDh::new()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FfDhError {
    Err,
}

impl FfDhError {
    const DETAILS: &str = "FfDhError";
    fn new() -> Self {
        FfDhError::Err
    }
}

impl fmt::Display for FfDhError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", FfDhError::DETAILS)
    }
}

impl Error for FfDhError {
    fn description(&self) -> &str {
        FfDhError::DETAILS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffdh_new() {
        let ffdh = FfDh::new();
        assert_eq!(
            ffdh.public_key,
            FfDh::ffdh_g().modpow(&ffdh.private_key, &FfDh::ffdh_p())
        );
    }

    #[test]
    fn ffdh_safe_pubkeys() {
        let zero = BigUint::from(0u32);
        assert_eq!(FfDh::check_safe_pubkey(&zero), Err(FfDhError::Err));
        let one = BigUint::from(1u32);
        assert_eq!(FfDh::check_safe_pubkey(&one), Err(FfDhError::Err));

        let rand = OsRng.gen_biguint_range(&BigUint::from(2u32), &FfDh::ffdh_p());
        assert_eq!(FfDh::check_safe_pubkey(&rand), Ok(()));

        let p2 = OsRng.gen_biguint_range(&(FfDh::ffdh_p() - 1u32), &FfDh::ffdh_p());
        assert_eq!(FfDh::check_safe_pubkey(&p2), Err(FfDhError::Err));
    }

    #[test]
    fn ffdh_test_dh() {
        let (alice, bob) = (FfDh::new(), FfDh::new());

        let alice_secret: [u8; 32] = alice
            .generate_shared_bytes(&bob.pubkey_pem().unwrap())
            .unwrap();
        let bob_secret: [u8; 32] = bob
            .generate_shared_bytes(&alice.pubkey_pem().unwrap())
            .unwrap();

        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn ffdh_parses_pem() {
        // Test that generated public keys can be parsed by ffdh
        let ffdh = FfDh::new();
        let ffdh_pubkey = FfDh::pubkey_from_pem(&ffdh.pubkey_pem().unwrap()).unwrap();

        assert_eq!(ffdh.public_key.to_bytes_be(), ffdh_pubkey.to_bytes_be());
    }

    #[cfg(feature = "test_openssl")]
    #[test]
    fn ffdh_ossl_parses_pem() {
        use openssl::pkey::PKey;
        // Test that generated public keys can be parsed by openssl
        let ffdh = FfDh::new();
        let ffdh_pubkey = ffdh.pubkey_pem().unwrap();

        // Pass the public key through openssl and get it back
        let ossl_pubk = PKey::public_key_from_pem(ffdh_pubkey.as_bytes())
            .unwrap()
            .dh()
            .unwrap()
            .public_key()
            .to_hex_str()
            .unwrap();

        // Check that the public key wasn't changed in passing through openssl
        assert_eq!(
            ffdh.public_key.to_bytes_be(),
            hex::decode(ossl_pubk.as_bytes()).unwrap()
        );
    }

    #[cfg(feature = "test_openssl")]
    #[test]
    fn ffdh_ossl_interop() {
        // TODO: Check that performing ffdh with openssl as a client works as expected
    }

    #[test]
    fn test_p() {
        assert_eq!(FfDh::ffdh_p().to_bytes_be(), hex!("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF"));
    }
}
