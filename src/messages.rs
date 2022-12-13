//! Stores message data. 
//! 
//! This crate has under-developed developer UX.

/// Message wraps up a message and associated data. This type is not ready for prime time (hence, byte arrays). This is more to sketch out what a "MVP" of a client-side message struct should contain.
/// 
/// - an address: this is the address to POST the message to on a hypothetical server (assuming the server acts as a key-value store/hashmap).
/// - a "public" key (*must be at a MINIMUM authenticated/signed*): the naming here is unfortunate, but this is a DH public key that should, as best practice, be encrypted alongside the message contents. Technically, the protocol's security guarantees apply so long as the public key cannot be tampered with, but it's easiest just to toss it through AEAD.
/// - the message content
pub struct Message {
    pub address: [u8; 32],
    pub public_key: [u8; 32],
    pub content: String,
}

impl Message {
    //! Wraps up data in a message.
    pub fn new(address: [u8; 32], public_key: [u8; 32], content: &str) -> Message {
        Message {
            address,
            public_key,
            content: content.to_string()
        }
    }
}