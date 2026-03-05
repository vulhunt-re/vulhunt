use std::marker::PhantomData;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use bias_core::any::ProvidesStaticType;
use bias_core::kb::{uuid, Uuid};
use bias_core::loader::{LoaderAttribute, LoaderContainer};

use super::{
    PlatformAttributeProvider, PlatformBuilder, PlatformComponentLoader, PlatformProvider,
};

#[derive(Clone)]
#[repr(transparent)]
pub struct Crypto<T>
where
    T: CryptoKind,
{
    kind: PhantomData<fn() -> T>,
}

pub trait CryptoKind {
    const NAME: &'static str;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CryptoAttribute {
    Name(String),
    Path(PathBuf),
}

impl CryptoAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct CryptoComponentName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for CryptoComponentName<'a> {
    const UUID: Uuid = uuid("8473B79F-6D46-460B-A15A-A2055D4094DF");
}

impl<'a> AsRef<str> for CryptoComponentName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for CryptoComponentName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct CryptoComponentPath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for CryptoComponentPath<'a> {
    const UUID: Uuid = uuid("B57BF6BF-D271-4DCB-8CF4-7C80F9F03BE4");
}

impl<'a> AsRef<Path> for CryptoComponentPath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for CryptoComponentPath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<T> PlatformProvider for Crypto<T>
where
    T: CryptoKind,
{
    type Attribute = CryptoAttribute;

    const NAME: &'static str = T::NAME;
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for CryptoAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(CryptoComponentName(name));
            }
            Self::Path(path) => {
                container.set_attr(CryptoComponentPath(path));
            }
        }
    }
}

pub type CryptoKeyBuilder<T> = PlatformBuilder<Crypto<T>>;
pub type CryptoCertificateBuilder<T> = PlatformBuilder<Crypto<T>>;
pub type CryptoPkcs7Builder<T> = PlatformBuilder<Crypto<T>>;
pub type CryptoPkcs12Builder<T> = PlatformBuilder<Crypto<T>>;

#[derive(Debug, Copy, Clone)]
pub struct PublicKeyPem;

impl CryptoKind for PublicKeyPem {
    const NAME: &'static str = "crypto.public-key.pem";
}

pub type PublicKeyPemBuilder = CryptoKeyBuilder<PublicKeyPem>;

#[derive(Debug, Copy, Clone)]
pub struct PublicKeyDer;

impl CryptoKind for PublicKeyDer {
    const NAME: &'static str = "crypto.public-key.der";
}

pub type PublicKeyDerBuilder = CryptoKeyBuilder<PublicKeyDer>;

#[derive(Debug, Copy, Clone)]
pub struct PublicKeyPgp;

impl CryptoKind for PublicKeyPgp {
    const NAME: &'static str = "crypto.public-key.pgp";
}

pub type PublicKeyPgpBuilder = CryptoKeyBuilder<PublicKeyPgp>;

#[derive(Debug, Copy, Clone)]
pub struct PublicKeySsh;

impl CryptoKind for PublicKeySsh {
    const NAME: &'static str = "crypto.public-key.ssh";
}

pub type PublicKeySshBuilder = CryptoKeyBuilder<PublicKeySsh>;

#[derive(Debug, Copy, Clone)]
pub struct PublicKeyTss2;

impl CryptoKind for PublicKeyTss2 {
    const NAME: &'static str = "crypto.public-key.tss2";
}

pub type PublicKeyTss2Builder = CryptoKeyBuilder<PublicKeyTss2>;

#[derive(Debug, Copy, Clone)]
pub struct PrivateKeyPem;

impl CryptoKind for PrivateKeyPem {
    const NAME: &'static str = "crypto.private-key.pem";
}

pub type PrivateKeyPemBuilder = CryptoKeyBuilder<PrivateKeyPem>;

#[derive(Debug, Copy, Clone)]
pub struct PrivateKeyDer;

impl CryptoKind for PrivateKeyDer {
    const NAME: &'static str = "crypto.private-key.der";
}

pub type PrivateKeyDerBuilder = CryptoKeyBuilder<PrivateKeyDer>;

#[derive(Debug, Copy, Clone)]
pub struct PrivateKeyPgp;

impl CryptoKind for PrivateKeyPgp {
    const NAME: &'static str = "crypto.private-key.pgp";
}

pub type PrivateKeyPgpBuilder = CryptoKeyBuilder<PrivateKeyPgp>;

#[derive(Debug, Copy, Clone)]
pub struct PrivateKeySsh;

impl CryptoKind for PrivateKeySsh {
    const NAME: &'static str = "crypto.private-key.ssh";
}

pub type PrivateKeySshBuilder = CryptoKeyBuilder<PrivateKeySsh>;

#[derive(Debug, Copy, Clone)]
pub struct PrivateKeyTss2;

impl CryptoKind for PrivateKeyTss2 {
    const NAME: &'static str = "crypto.private-key.tss2";
}

pub type PrivateKeyTss2Builder = CryptoKeyBuilder<PrivateKeyTss2>;

#[derive(Debug, Copy, Clone)]
pub struct CertificatePem;

impl CryptoKind for CertificatePem {
    const NAME: &'static str = "crypto.certificate.pem";
}

pub type CertificatePemBuilder = CryptoCertificateBuilder<CertificatePem>;

#[derive(Debug, Copy, Clone)]
pub struct CertificateDer;

impl CryptoKind for CertificateDer {
    const NAME: &'static str = "crypto.certificate.der";
}

pub type CertificateDerBuilder = CryptoCertificateBuilder<CertificateDer>;

#[derive(Debug, Copy, Clone)]
pub struct Pkcs7Pem;

impl CryptoKind for Pkcs7Pem {
    const NAME: &'static str = "crypto.pkcs7.pem";
}

pub type Pkcs7PemBuilder = CryptoPkcs7Builder<Pkcs7Pem>;

#[derive(Debug, Copy, Clone)]
pub struct Pkcs7Der;

impl CryptoKind for Pkcs7Der {
    const NAME: &'static str = "crypto.pkcs7.der";
}

pub type Pkcs7DerBuilder = CryptoPkcs7Builder<Pkcs7Der>;

// PEM format for PKCS#12 is uncommon, but can be used
#[derive(Debug, Copy, Clone)]
pub struct Pkcs12Pem;

impl CryptoKind for Pkcs12Pem {
    const NAME: &'static str = "crypto.pkcs12.pem";
}

pub type Pkcs12PemBuilder = CryptoPkcs12Builder<Pkcs12Pem>;

#[derive(Debug, Copy, Clone)]
pub struct Pkcs12Der;

impl CryptoKind for Pkcs12Der {
    const NAME: &'static str = "crypto.pkcs12.der";
}

pub type Pkcs12DerBuilder = CryptoPkcs12Builder<Pkcs12Der>;
