use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};

use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, Id, PKey, PKeyRef, Private, Public};
use openssl::sign::{Signer, Verifier};

pub use hex;
pub use serde;

pub use error::Error;
pub use id::DeviceID;

mod error;
mod id;
mod ser;
mod utils;

/// digest method for compute id
const NID_BLAKE2B512: i32 = 1056;

/// RingLink identity
#[derive(Clone)]
pub struct Identity {
    id: DeviceID,
    raw_sign: Vec<u8>,
    pkey: PKey<Private>,
}

/// Public part of RingLink [Identity]
#[derive(Clone)]
pub struct PublicIdentity {
    id: DeviceID,
    raw_sign: Vec<u8>,

    pkey: PKey<Public>,
}

impl Identity {
    /// Generate new RingLink Identity
    pub fn generate() -> Result<Identity, Error> {
        let sign = PKey::generate_ed25519()?;

        let pk = sign.raw_public_key()?;
        let id = compute_address(&pk)?;

        Ok(Identity {
            id,
            raw_sign: sign.raw_private_key()?,
            pkey: sign,
        })
    }

    /// Sign data with Identity
    ///
    /// # Arguments
    /// * `data` - Data to sign
    pub fn sign(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        let mut signer = Signer::new_without_digest(&self.pkey)?;

        let signature = signer.sign_oneshot_to_vec(data.as_ref())?;

        Ok(signature)
    }

    /// Verify signature with Identity
    pub fn verify(
        &self,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        verify(&self.pkey, data, signature)
    }

    /// Get public part of Identity
    ///
    /// # Error
    /// Return error if public key is not available
    pub fn public_identity(&self) -> Result<PublicIdentity, Error> {
        PublicIdentity::new_with_id(self.id, self.pkey.raw_public_key()?)
    }

    /// Unique ID of Identity
    pub fn id(&self) -> DeviceID {
        self.id
    }

    /// Get raw private key
    pub fn private_key(&self) -> &[u8] {
        &self.raw_sign
    }
}

impl Hash for Identity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.raw_sign.hash(state);
    }
}

impl Eq for Identity {}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        self.id.eq(&other.id) && self.raw_sign.eq(&other.raw_sign)
    }
}

impl Debug for Identity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("Identity");
        f.field("id", &self.id);

        match self.pkey.raw_public_key() {
            Ok(pk) => f.field("sign", &pk),
            Err(_) => f.field("sign", &"not available"),
        };

        f.finish()
    }
}

impl PublicIdentity {
    pub(crate) fn new_with_id(
        id: DeviceID,
        sign: impl AsRef<[u8]>,
    ) -> Result<PublicIdentity, Error> {
        let pkey = PKey::public_key_from_raw_bytes(sign.as_ref(), Id::ED25519)?;

        Ok(PublicIdentity {
            id,
            raw_sign: sign.as_ref().to_vec(),
            pkey,
        })
    }

    /// Construct PublicIdentity from public keys
    ///
    /// # Arguments
    /// * `sign` - Public key for signing, normally get from [Identity::public_identity]
    pub fn new(sign: impl AsRef<[u8]>) -> Result<PublicIdentity, Error> {
        let id = compute_address(sign.as_ref())?;

        Self::new_with_id(id, sign)
    }

    /// Verify signature with [PublicIdentity]
    pub fn verify(
        &self,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        verify(&self.pkey, data, signature)
    }

    /// Unique ID of Identity
    pub fn id(&self) -> DeviceID {
        self.id
    }

    /// Get raw public key of Identity
    ///
    /// The returned value can be used to construct a new [PublicIdentity]
    pub fn public_key(&self) -> &[u8] {
        &self.raw_sign
    }
}

impl Hash for PublicIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.raw_sign.hash(state);
    }
}

impl Eq for PublicIdentity {}

impl PartialEq for PublicIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.id.eq(&other.id) && self.raw_sign.eq(&other.raw_sign)
    }
}

impl Debug for PublicIdentity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("PublicIdentity");
        f.field("id", &self.id);
        match self.pkey.raw_public_key() {
            Ok(pk) => f.field("sign", &pk),
            Err(_) => f.field("sign", &"not available"),
        };

        f.finish()
    }
}

fn compute_address(public_key: &[u8]) -> Result<DeviceID, Error> {
    let nid = Nid::from_raw(NID_BLAKE2B512);
    let md = MessageDigest::from_nid(nid).expect("no message digest");

    let mut first = openssl::hash::hash(md, public_key)?;
    for _ in 0..31 {
        first = openssl::hash::hash(md, &first)?;
    }

    Ok(DeviceID::from_bytes(
        first[0..DeviceID::LENGTH].try_into().unwrap(),
    ))
}

fn verify<T: HasPublic>(
    key: &PKeyRef<T>,
    data: impl AsRef<[u8]>,
    signature: impl AsRef<[u8]>,
) -> Result<bool, Error> {
    let mut verifier = Verifier::new_without_digest(key)?;
    let ok = verifier.verify_oneshot(signature.as_ref(), data.as_ref())?;

    Ok(ok)
}
