#[macro_export]
macro_rules! declare_id {
    ($name:ident, $len:expr) => {
        #[derive(Clone, Copy, Eq, PartialEq, Hash, Default, Ord, PartialOrd)]
        #[repr(transparent)]
        pub struct $name([u8; $len]);

        impl $name {
            pub const LENGTH: usize = $len;

            pub const fn from_bytes(inner: [u8; $len]) -> $name {
                $name(inner)
            }
        }

        impl From<[u8; $name::LENGTH]> for $name {
            fn from(inner: [u8; $name::LENGTH]) -> Self {
                $name::from_bytes(inner)
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $crate::hex::FromHexError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let mut id = $name::default();

                $crate::hex::decode_to_slice(s, &mut id.0)?;

                Ok(id)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = $crate::Error;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                Ok($name(
                    value.try_into().map_err(|_| $crate::Error::InvalidLength)?,
                ))
            }
        }

        impl TryFrom<Vec<u8>> for $name {
            type Error = $crate::Error;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                <Self as TryFrom<&[u8]>>::try_from(&*value)
            }
        }

        impl ::core::ops::Deref for $name {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl ::core::ops::DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&self.to_string())
                    .finish()
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(&$crate::hex::encode(&self.0))
            }
        }

        impl $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                $crate::hex::serialize(self.0, serializer)
            }
        }

        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: $crate::serde::Deserializer<'de>,
            {
                $crate::hex::deserialize(deserializer).map($name::from_bytes)
            }
        }
    };
}
