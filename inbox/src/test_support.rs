//! Ghost Keys under a throwaway authority, for tests in other crates.
//!
//! A certificate minted here verifies only against its own
//! [`TestAuthority::master`], never against Freenet's production master key,
//! so nothing built with this feature can write to a production inbox.

use ed25519_dalek::{Signer, SigningKey};
use freenet_bitcoin_common::{to_cbor, BridgeId};
use freenet_stdlib::prelude::ContractInstanceId;
use ghostkey_common::{ScopedPayload, SignatureRequestor};
use ghostkey_lib::armorable::Armorable;
use ghostkey_lib::ghost_key_certificate::GhostkeyCertificateV1;
use ghostkey_lib::notary_certificate::NotaryCertificateV1;
use ghostkey_lib::util::create_keypair;
use rand::rngs::OsRng;

use crate::{GhostkeyId, InboxEntryBody, InboxParameters, MasterKey, Sealed, WireEntry};

/// A master key and notary, standing in for Freenet's Ghost Key authority.
pub struct TestAuthority {
    pub master: MasterKey,
    notary: NotaryCertificateV1,
    notary_sk: blind_rsa_signatures::SecretKey,
}

impl Default for TestAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl TestAuthority {
    /// Generates an RSA notary key, which takes a moment: make one per test
    /// binary rather than one per test.
    pub fn new() -> Self {
        let (master_sk, master_vk) = create_keypair(&mut OsRng).expect("master keypair");
        let (notary, notary_sk) = NotaryCertificateV1::new(&master_sk, &"test notary".to_string())
            .expect("notary certificate");
        TestAuthority {
            master: MasterKey(*master_vk.as_bytes()),
            notary,
            notary_sk,
        }
    }

    /// The inbox `bridge` would run if this were the real authority.
    pub fn params(&self, bridge: BridgeId) -> InboxParameters {
        InboxParameters {
            bridge,
            ghostkey_master: self.master,
        }
    }

    /// A new Ghost Key certified by this authority.
    pub fn mint(&self) -> TestGhostkey {
        let (cert, sk) = GhostkeyCertificateV1::new(&self.notary, &self.notary_sk);
        TestGhostkey {
            sk,
            pem: cert.to_armored_string().expect("certificate armours"),
        }
    }
}

/// A Ghost Key and its certificate.
pub struct TestGhostkey {
    pub sk: SigningKey,
    pub pem: String,
}

impl TestGhostkey {
    pub fn id(&self) -> GhostkeyId {
        GhostkeyId(self.sk.verifying_key().to_bytes())
    }

    /// An entry as a web app would send it: `sealed`, for `bridge`'s inbox,
    /// dated `mainnet_height` and signed by this Ghost Key.
    pub fn entry(&self, bridge: BridgeId, mainnet_height: u32, sealed: Sealed) -> WireEntry {
        let body = InboxEntryBody {
            bridge,
            mainnet_height,
            sealed,
        };
        let scoped = to_cbor(&ScopedPayload {
            requestor: SignatureRequestor::WebApp(ContractInstanceId::new([7u8; 32])),
            payload: body.signing_payload().expect("body encodes"),
        })
        .expect("scoped payload encodes");
        let sig = self.sk.sign(&scoped).to_bytes().to_vec();
        WireEntry::from_sign_result(self.pem.clone(), scoped, sig)
            .expect("a freshly minted entry is well formed")
    }
}
