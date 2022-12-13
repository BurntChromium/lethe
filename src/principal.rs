//! The Principal is a participant in a conversation. We split this into two structures: a pre-handshake principal and a post-handshake principal. This code handles the (modified) double-ratchet protocol required to handle pseudo-random addresses.

use anyhow;
use hex;
use rand_core::{RngCore, OsRng};
use x25519_dalek::{EphemeralSecret, ReusableSecret, PublicKey, SharedSecret};
use sha2::Sha256;
use hkdf::Hkdf;

use crate::messages::{Message};

/// ADDRESS_LENGTH is 32 bytes
pub const ADDRESS_LENGTH: usize = 32;
/// NONCE_LENGTH is 16 bytes
pub const NONCE_LENGTH: usize = 16;
/// ADDRESS_CONTEXT_BYTES modifies the nonce so the HKDF can generate separate addresses and keys ("address" then 9 null bytes)
const ADDRESS_CONTEXT_BYTES: [u8; 16] = [97, 100, 100, 114, 101, 115, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// KEY_CONTEXT_BYTES modifies the nonce so the HKDF can generate separate addresses and keys ("key" then 13 null bytes)
const KEY_CONTEXT_BYTES: [u8; 16] = [107, 101, 121, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ];
/// LOOKAHEAD_COUNTERPARTY is the number of addresses pre-compute for the counterparty
pub const LOOKAHEAD_COUNTERPARTY: usize = 4;

/// PrincipalBeforeHandshake defines the pre-handshake clients/principals. This should essentially be considered an initialization/builder structure for the Principal struct. The reason to split pre- and post- handshake principals is that the data held is very different: pre-handshake you need keypairs, and post-handshake you need to maintain (shared) keyrings.
pub struct PrincipalBeforeHandshake {
    chat_name: String,
    root_secret: EphemeralSecret, // this gets consumed
    root_public: PublicKey,
    ephemeral_secret: ReusableSecret, // this gets reused *once* in the Double Ratchet
    ephemeral_public: PublicKey,
    nonce: [u8; NONCE_LENGTH]
}

impl PrincipalBeforeHandshake {
    /// new builds a new pre-handshake principal using randomly generated keys
    pub fn new(name: &str) -> Self {
        let mut new_nonce = [0u8; NONCE_LENGTH];
        OsRng.fill_bytes(&mut new_nonce);
        let new_root_secret = EphemeralSecret::new(OsRng);
        let new_ephemeral_secret = ReusableSecret::new(OsRng);
        Self {
            chat_name: name.to_string(),
            root_public: PublicKey::from(&new_root_secret),
            ephemeral_public: PublicKey::from(&new_ephemeral_secret),
            root_secret: new_root_secret,
            ephemeral_secret: new_ephemeral_secret,
            nonce: new_nonce
        }
    }

    /// export_for_handshake converts the root public key, ephemeral public key, and nonce to a string seprated by "." for transport across a network: "<hex-root-public-key>.<hex-ephm-public-key>.<hex-nonce>"
    ///
    /// Example: 482c2e22b71825246f61f9cd771e4d72e769daba376a9a2140476f59f312de05.75c62514e1a32811e967b60e0162e46b9a697ffcb9023e76b8a8db8f76982530.a5a1b1d128116a3c8ccaf7337b4f7d3e
    pub fn export_for_handshake(&self) -> String {
        hex::encode(self.root_public.as_bytes()) + "." + &hex::encode(self.ephemeral_public.as_bytes()) + "." + &hex::encode(self.nonce)
    }
}

/// Principal is a participant in a conversation (borrowing the language from Verifpal).
///
/// Fields:
///
/// - chat_name: user defined name for this conversation/counter party
///
/// - sent_last_message: when sending multiple messages there's only a KDF ratchet. 
/// When *responding* to a message, there's a DH ratchet + a KDF ratchet.
///
/// - ephemeral_public: after performing a DH ratchet, the principal needs to send their new public key.
///
/// - ephemeral_secret: while this is labelled "ephemeral" (it does rotate out). it uses the 'reusable' type because the double ratchet has to use every secret key twice
/// 
/// - ephemeral_shared: the derived shared secret
///
/// - chain_key: part of the KDF ratchet output used to create more keying material
///
/// - next_address: where the next message should be sent to
///
/// - counterparty_ephemeral_public: public key of whoever you're talking to (unique to this chat thread)
///
/// - counterparty_address: where your counterparty will post their next message
///
/// - counterparty_chain_key: material your counterparty will use to derive their next address (necessary for bookkeeping)

pub struct Principal {
    pub chat_name: String,
    sent_last_message: bool,
    ephemeral_public: PublicKey,
    ephemeral_secret: ReusableSecret,
    ephemeral_shared: SharedSecret,
    chain_key: [u8; 32],
    next_address: [u8; 32],
    counterparty_ephemeral_public: PublicKey,
    counterparty_address: [u8; 32],
    counterparty_chain_key: [u8; 32]
}

/// Handshake is just an ergonomic alternative to using a tuple
struct Handshake {
    pub root_public: PublicKey,
    pub ephemeral_public: PublicKey,
    pub nonce: [u8; NONCE_LENGTH]
}

impl Principal {
    /// parse_handshake converts the hex encoded handshake into a nicely formatted struct
    fn parse_handshake(handshake: &str) -> Result<Handshake, anyhow::Error> {
        // Parse the handshake string
        let split_handshake = handshake.split('.');
        let handshake_parts = split_handshake.collect::<Vec<&str>>();
        // Check that handshake is the right length
        if handshake_parts.len() != 3 {
            anyhow::bail!("handshake is not 3 parts (should be public root key + public ephmeral key + nonce)");
        }
        // Extract byte arrays from the string for each part
        let mut counterparty_root_bytes = [0u8; 32];
        let mut counterparty_ephm_bytes = [0u8; 32];
        let mut counterparty_nonce = [0u8; NONCE_LENGTH];
        hex::decode_to_slice(handshake_parts[0], &mut counterparty_root_bytes)?;
        hex::decode_to_slice(handshake_parts[1], &mut counterparty_ephm_bytes)?;
        hex::decode_to_slice(handshake_parts[2], &mut counterparty_nonce)?;
        // return
        Ok(Handshake {
            root_public: PublicKey::from(counterparty_root_bytes),
            ephemeral_public: PublicKey::from(counterparty_ephm_bytes),
            nonce: counterparty_nonce
        })
    }

    /// new creates a principal from an initilization struct and a counter party's handshake string.
    /// the error return is a "generic" type to bubble up whatever weird errors crop up from dependencies.
    pub fn new(initialization: PrincipalBeforeHandshake, handshake: &str) -> Result<Principal, anyhow::Error> {
        let decoded_handshake = Self::parse_handshake(handshake)?;
        // Compute shared secrets
        let chain_key: SharedSecret = initialization.root_secret.diffie_hellman(&decoded_handshake.root_public);
        let ephemeral_shared: SharedSecret = initialization.ephemeral_secret.diffie_hellman(&decoded_handshake.ephemeral_public);
        // Use HKDF to compute addresses and keys for this principal (salt = ephm shared, ikm = root/chain key, nonce is info)
        let context_address = [initialization.nonce, ADDRESS_CONTEXT_BYTES].concat();
        let context_key = [initialization.nonce, KEY_CONTEXT_BYTES].concat();
        let kdf_mine = Hkdf::<Sha256>::new(Some(ephemeral_shared.as_bytes()), chain_key.as_bytes());
        let mut address_mine = [0u8; ADDRESS_LENGTH];
        kdf_mine.expand(&context_address, &mut address_mine)?;
        let mut next_chain_key_mine = [0u8; ADDRESS_LENGTH];
        kdf_mine.expand(&context_key, &mut next_chain_key_mine)?;
        // Use HKDF to compute first address and key for counterparty
        let context_address_cp = [decoded_handshake.nonce, ADDRESS_CONTEXT_BYTES].concat();
        let context_key_cp = [decoded_handshake.nonce, KEY_CONTEXT_BYTES].concat();
        let kdf_cp = Hkdf::<Sha256>::new(Some(ephemeral_shared.as_bytes()), chain_key.as_bytes());
        let mut address_cp = [0u8; ADDRESS_LENGTH];
        kdf_cp.expand(&context_address_cp, &mut address_cp)?;
        let mut next_chain_key_cp = [0u8; ADDRESS_LENGTH];
        kdf_cp.expand(&context_key_cp, &mut next_chain_key_cp)?;
        // Construct new object 
        Ok(
            Principal {
                chat_name: initialization.chat_name,
                sent_last_message: false,
                ephemeral_public: initialization.ephemeral_public,
                ephemeral_secret: initialization.ephemeral_secret,
                ephemeral_shared,
                chain_key: next_chain_key_mine,
                next_address: address_mine,
                counterparty_ephemeral_public: decoded_handshake.ephemeral_public,
                counterparty_address: address_cp,
                counterparty_chain_key: next_chain_key_cp
            }
        )
    }

    /// kdf_ratchet runs the KDF ratchet to update state on self
    fn kdf_ratchet(&mut self) -> Result<(), anyhow::Error> {
        // KDF ratchet for self
        let kdf = Hkdf::<Sha256>::new(Some(self.ephemeral_shared.as_bytes()), &self.chain_key);
        let mut next_address = [0u8; ADDRESS_LENGTH];
        kdf.expand(&ADDRESS_CONTEXT_BYTES, &mut next_address)?;
        let mut next_chain_key = [0u8; ADDRESS_LENGTH];
        kdf.expand(&KEY_CONTEXT_BYTES, &mut next_chain_key)?;
        // KDF ratchet for counterparty
        let kdf_cp = Hkdf::<Sha256>::new(Some(self.ephemeral_shared.as_bytes()), &self.counterparty_chain_key);
        let mut next_address_cp = [0u8; ADDRESS_LENGTH];
        kdf_cp.expand(&ADDRESS_CONTEXT_BYTES, &mut next_address_cp)?;
        let mut next_chain_key_cp = [0u8; ADDRESS_LENGTH];
        kdf_cp.expand(&KEY_CONTEXT_BYTES, &mut next_chain_key_cp)?;
        // Update self
        self.next_address = next_address;
        self.chain_key = next_chain_key;
        self.counterparty_address = next_address_cp;
        self.counterparty_chain_key = next_chain_key_cp;
        Ok(())
    }

    /// parse_message consumes a message object, updates state, and returns the content
    pub fn parse_message(&mut self, message: Message) -> Result<String, anyhow::Error> {
        // If this public key is new, get a new shared secret
        let counterparty_new_public_key = PublicKey::from(message.public_key);
        if &message.public_key != self.counterparty_ephemeral_public.as_bytes() {
            self.ephemeral_shared = self.ephemeral_secret.diffie_hellman(&counterparty_new_public_key);
            self.counterparty_ephemeral_public = counterparty_new_public_key;
        }
        // Run KDF ratchet / update state
        self.kdf_ratchet()?;
        self.sent_last_message = false;
        // Return message for processing
        Ok(message.content)
    }

    /// prepare_message performs the necessary ratcheting operations
    ///
    /// Note: we do not re-use the nonce (by definition...). We don't need to: the input keys to the ratchet were already "flavored" by the nonce during initialization.
    pub fn prepare_message(&mut self, input_text: &str) -> Result<Message, anyhow::Error> {
        // First, a branch that *should* never be entered -> if next address is not fresh, abort
        if self.next_address == [0u8; 32] {
            // Note: above comparison leaks timing information
            anyhow::bail!("message address is stale, this breaks security guarantees.");
        }
        let message: Message;
        if self.sent_last_message {
            // Create output (u8 has copy so this dereference isn't a move)
            message = Message::new(self.next_address, *self.ephemeral_public.as_bytes(), input_text); 
            // Run KDF ratchet
            self.kdf_ratchet()?;
            self.sent_last_message = true;
        } else {
            // We are responding to a message, so run a DH ratchet
            let new_ephemeral_secret = ReusableSecret::new(OsRng);
            let new_ephemeral_public = PublicKey::from(&new_ephemeral_secret);
            let new_ephemeral_shared = new_ephemeral_secret.diffie_hellman(&self.counterparty_ephemeral_public);
            // Prepare message, including new public key
            message = Message::new(self.next_address, *new_ephemeral_public.as_bytes(), input_text);
            // Update self with new DH info
            self.ephemeral_public = new_ephemeral_public;
            self.ephemeral_secret = new_ephemeral_secret;
            self.ephemeral_shared = new_ephemeral_shared;
            // Run KDF ratchet
            self.kdf_ratchet()?;
            self.sent_last_message = true;
        }
        // Return message
        Ok(message)
    }
}

/* ------------------------------------------------------------------------- */

// TESTS 

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_prehandshake_principal() {
        let principal = PrincipalBeforeHandshake::new("bob");
        // Check nonce length
        assert_eq!(principal.nonce.len(), 16);
        // Check name
        assert_eq!(principal.chat_name, "bob".to_string());
    }

    #[test]
    fn check_handshake_string() {
        let principal = PrincipalBeforeHandshake::new("bob");
        let handshake_str = principal.export_for_handshake();
        // Check that there are two periods
        let delimiter_count = handshake_str.matches(".").count();
        assert_eq!(delimiter_count, 2);
        let split_handshake = handshake_str.split(".");
        let handshake_parts = split_handshake.collect::<Vec<&str>>();
        assert_eq!(handshake_parts.len(), 3);
        // Check component strings decode back
        let mut root_bytes = [0u8; 32];
        let mut ephm_bytes = [0u8; 32];
        let mut nonce = [0u8; 16];
        hex::decode_to_slice(handshake_parts[0], &mut root_bytes).unwrap();
        hex::decode_to_slice(handshake_parts[1], &mut ephm_bytes).unwrap();
        hex::decode_to_slice(handshake_parts[2], &mut nonce).unwrap();
        assert_eq!(&root_bytes, principal.root_public.as_bytes());
        assert_eq!(&ephm_bytes, principal.ephemeral_public.as_bytes());
        assert_eq!(nonce, principal.nonce);
    }

    #[test]
    fn parse_handshake() {
        let pre_principal = PrincipalBeforeHandshake::new("bob");
        let handshake_str = pre_principal.export_for_handshake();
        let result = Principal::parse_handshake(&handshake_str).expect("parsing procedure caused a runtime exception");
        assert_eq!(pre_principal.root_public.as_bytes(), result.root_public.as_bytes());
        assert_eq!(pre_principal.ephemeral_public.as_bytes(), result.ephemeral_public.as_bytes());
        assert_eq!(pre_principal.nonce, result.nonce);
    }

    #[test]
    fn test_handshake() {
        let alice_pre = PrincipalBeforeHandshake::new("chat with bob");
        let bob_pre = PrincipalBeforeHandshake::new("chat with alice");
        let alice_handshake = alice_pre.export_for_handshake();
        let bob_handshake = bob_pre.export_for_handshake();
        let alice = Principal::new(alice_pre, &bob_handshake).expect("alice failed to build");
        let bob = Principal::new(bob_pre, &alice_handshake).expect("bob failed to build");
        // Check that Alice and Bob's shared secrets agree
        assert_eq!(alice.ephemeral_shared.as_bytes(), bob.ephemeral_shared.as_bytes());
        assert_eq!(alice.next_address, bob.counterparty_address);
        assert_eq!(bob.next_address, alice.counterparty_address);
        assert_eq!(alice.chain_key, bob.counterparty_chain_key);
        assert_eq!(bob.chain_key, alice.counterparty_chain_key);
    }

    #[test]
    fn test_messages_abab() {
        // Alice sends, then Bob, then Alice, then Bob
        let alice_pre = PrincipalBeforeHandshake::new("chat with bob");
        let bob_pre = PrincipalBeforeHandshake::new("chat with alice");
        let alice_handshake = alice_pre.export_for_handshake();
        let bob_handshake = bob_pre.export_for_handshake();
        let mut alice = Principal::new(alice_pre, &bob_handshake).expect("alice failed to build");
        let mut bob = Principal::new(bob_pre, &alice_handshake).expect("bob failed to build");
        // Check initial addresses are equal
        assert_eq!(alice.next_address, bob.counterparty_address);
        assert_eq!(bob.next_address, alice.counterparty_address);
        // Send messages (message address needs to match address counterparty expects to find)
        // Message 1
        let a1 = alice.prepare_message("message 1");
        assert_eq!(a1.as_ref().unwrap().address, bob.counterparty_address);
        let _ = bob.parse_message(a1.unwrap());
        // Message 2
        let b2 = bob.prepare_message("message 2");
        assert_eq!(b2.as_ref().unwrap().address, alice.counterparty_address);
        let _ = alice.parse_message(b2.unwrap());
        // Message 2
        let a3 = alice.prepare_message("message 3");
        assert_eq!(a3.as_ref().unwrap().address, bob.counterparty_address);
        let _ = bob.parse_message(a3.unwrap());
        // Message 4
        let b4 = bob.prepare_message("message 4");
        assert_eq!(b4.as_ref().unwrap().address, alice.counterparty_address);
        let _ = alice.parse_message(b4.unwrap());
    }

    #[test]
    fn test_messages_aaabba() {
        // Alice sends, then Bob, then Alice, then Bob
        let alice_pre = PrincipalBeforeHandshake::new("chat with bob");
        let bob_pre = PrincipalBeforeHandshake::new("chat with alice");
        let alice_handshake = alice_pre.export_for_handshake();
        let bob_handshake = bob_pre.export_for_handshake();
        let mut alice = Principal::new(alice_pre, &bob_handshake).expect("alice failed to build");
        let mut bob = Principal::new(bob_pre, &alice_handshake).expect("bob failed to build");
        // Check initial addresses are equal
        assert_eq!(alice.next_address, bob.counterparty_address);
        assert_eq!(bob.next_address, alice.counterparty_address);
        // Send messages (message address needs to match address counterparty expects to find)
        // Message 1
        let a1 = alice.prepare_message("message 1");
        assert_eq!(a1.as_ref().unwrap().address, bob.counterparty_address);
        let _ = bob.parse_message(a1.unwrap());
        assert_eq!(alice.next_address, bob.counterparty_address);
        assert_eq!(bob.next_address, alice.counterparty_address);
        // Message 2
        let a2 = alice.prepare_message("message 2");
        assert_eq!(a2.as_ref().unwrap().address, bob.counterparty_address);
        let _ = bob.parse_message(a2.unwrap());
        // Message 3
        let a3 = alice.prepare_message("message 3");
        assert_eq!(a3.as_ref().unwrap().address, bob.counterparty_address);
        let _ = bob.parse_message(a3.unwrap());
        // Message 4
        let b4 = bob.prepare_message("message 4");
        assert_eq!(b4.as_ref().unwrap().address, alice.counterparty_address);
        let _ = alice.parse_message(b4.unwrap());
        assert_eq!(alice.next_address, bob.counterparty_address);
        assert_eq!(bob.next_address, alice.counterparty_address);
        // Message 5
        let b5 = bob.prepare_message("message 5");
        assert_eq!(b5.as_ref().unwrap().address, alice.counterparty_address);
        let _ = alice.parse_message(b5.unwrap());
        // Message 6
        let a6 = alice.prepare_message("message 6");
        assert_eq!(a6.as_ref().unwrap().address, bob.counterparty_address);
        let _ = bob.parse_message(a6.unwrap());
        assert_eq!(alice.next_address, bob.counterparty_address);
        assert_eq!(bob.next_address, alice.counterparty_address);
    }
}
