use std::str::FromStr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openssl::pkey::{Id, PKey};
use serde::de::Unexpected;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{DeviceID, Identity, PublicIdentity};

impl Serialize for Identity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("Identity", 3)?;
        let id = hex::encode(&*self.id);
        s.serialize_field("id", &id)?;

        let sign_key = STANDARD.encode(&self.raw_sign);
        s.serialize_field("sign", &sign_key)?;

        s.end()
    }
}

impl<'de> Deserialize<'de> for Identity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        #[derive(Deserialize)]
        struct IdentityPlain {
            id: String,
            sign: String,
        }

        let identity: IdentityPlain = IdentityPlain::deserialize(deserializer)?;

        let id = DeviceID::from_str(&identity.id)
            .map_err(|_| Error::invalid_value(Unexpected::Str(&identity.id), &"device id"))?;

        let raw_sign = STANDARD.decode(&identity.sign).map_err(|_| {
            Error::invalid_value(Unexpected::Str(&identity.sign), &"base64 encoded")
        })?;
        let pkey = PKey::private_key_from_raw_bytes(&raw_sign, Id::ED25519)
            .map_err(|e| Error::custom(format!("{}", e)))?;

        Ok(Identity { id, raw_sign, pkey })
    }
}

impl Serialize for PublicIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("PublicIdentity", 3)?;
        s.serialize_field("id", &self.id)?;

        let sign = STANDARD.encode(&self.raw_sign);
        s.serialize_field("sign", &sign)?;

        s.end()
    }
}

impl<'de> Deserialize<'de> for PublicIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        #[derive(Deserialize)]
        struct IdentityPlain {
            id: DeviceID,
            sign: String,
        }

        let identity: IdentityPlain = IdentityPlain::deserialize(deserializer)?;

        let raw_sign = STANDARD.decode(&identity.sign).map_err(|_| {
            Error::invalid_value(Unexpected::Str(&identity.sign), &"base64 encoded")
        })?;
        let pkey = PKey::public_key_from_raw_bytes(&raw_sign, Id::ED25519)
            .map_err(|e| Error::custom(format!("{}", e)))?;

        Ok(PublicIdentity {
            id: identity.id,
            raw_sign,
            pkey,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::Identity;

    #[test]
    fn test_serialize() {
        let identity = Identity::generate().unwrap();

        let json = serde_json::to_string(&identity).unwrap();

        let identity2: Identity = serde_json::from_str(&json).unwrap();

        assert_eq!(identity, identity2);
    }
}
