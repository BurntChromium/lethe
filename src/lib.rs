//! # Lethe Library (Client Side)
//!
//! A pure rust implementation of the Lethe protocol for anonymous messaging. None of the functions are publicly exposed. This is on purpose. This library is not ready for use.
//!
//! ### Warnings and Disclaimers
//! 
//! - DO NOT USE IN PRODUCTION: this library and it's protocol have NOT been audited.
//! - This is a proof of concept, and is NOT considered ready to use from a code-completeness standpoint. This MVP has a number of foot-guns, which may be "sanded off" with future releases.
//! - This code is NOT meant for consumer use, and would be suitable only for protocol developers.
//! - This library/the associated protocol does NOT encrypt any data. Any "real world" implementation of this protocol requires authenticated encryption for its security guarantees (so, use a suitable AEAD cipher like XChaCha20-Poly1305 or AES-GCM).
//! 
//! ### Examples / API
//! 
//! Suppose that Alice and Bob want to chat. Alice first prepares some data to perform a key-exchange (the "handshake") with Bob.
//!
//! ```rust
//! let alice_keys_to_share_with_bob = PrincipalBeforeHandshake::new("Bob");
//! let handshake_str = alice_keys_to_share_with_bob.export_for_handshake();
//! ```
//!
//! Alice shares her handshake string with Bob, and Bob shares his handshake string with Alice. **This should happen "offline" or over a "trusted channel."** Examples of suitable procedures would be a QR code scan, or using the Signal messenger.
//!
//! Once Alice receives Bob's handshake string, she creates a new struct to manage her keyring going forward.
//! 
//! ```rust
//! let alice = Principal::new(alice_keys_to_share_with_bob, &bob_handshake).expect("alice failed to initalize properly");
//! ```
//! 
//! Alice can now prepare a message to send to Bob. **The new "public" key and the message contents should be encrypted using an AEAD cipher** (this is calleda public key because of the role it plays in a Diffie-Helman key exchange, but it actually needs to be, at a minimum, authenticated to protect against MITM attacks). This message would be sent to the server, which would store it at the address provided. 
//! 
//! ```rust
//! let a1 = alice.prepare_message("Hi Bob, did you know that cats are awesome?");
//! ```
//!
//! If Bob sends back a message to Alice (b2), she can parse it as follows.
//! 
//! ```rust
//! let message_contents = alice.parse_message(b2.unwrap());
//! ```
//! 
//! Alice and Bob continue sending messages to each other.
//!
//! ### Under the Hood
//! 
//! The pre- and post-handshake Principal structs are really just key management structs (these are cryptographic keys that have been repurposed to serve as message addresses). They are separated because the data required before and after is significantly different, and this avoids making everything into an Optional field. 
//! 
//! The reason we pass every message through these structs is so that we can update the state properly. Every time a message is sent or received, the principal(s) update their keyrings with fresh keys. Messages sent include an address to send the message to, a key, and the message content. **The latter two must be protected using AEAD.**

mod messages;
mod principal;