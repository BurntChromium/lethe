# Lethe (Client)

**WARNING**: this library is not intended for production use. It has not been audited. The protocol has not been peer reviewed.

This repository contains a proof of concept for a client-side library for an anonymous (direct) messaging protocol, and a formal verification script (using Verifpal) for said protocol. The basic idea is for each participant in a conversation to post every message to a new (pseudo) random address. Only participants in the conversation should be able to link any two addresses together: an outside observer should not be able to identify who is talking to whom.

This implementation is a **PROOF OF CONCEPT ONLY** (and even then, a proof of concept of the address protocol **only** and missing, intentionally, many required components for actual practical use). Again, the focus of this implementation is on demonstrating anonymity and **not** confidentiality; we do not offer any encryption of messages.

### To-Do's

- Allow 'look-ahead' of counterparty addresses / chain keys for out-of-order messages

## Documentation 

Code: `cargo doc --no-deps --open --document-private-items`

### Protocol Overview (see full writeup document)

(More details available in the [`protocol writeup`](protocol-writeup.md) file.)

This protocol is a straightforward adaption of the [double-ratchet algorithm](https://signal.org/docs/specifications/doubleratchet/) (DRA) to handle "addresses" rather than encryption keys. The only significant departure from the DRA is that instead of keeping a synchronized keychain between both parties we instead "season" the keychain of both parties in the conversation with a nonce during the handshake phase so that they have different "flavors." This avoids Alice and Bob accidentally trying to post to the same address. Alice and Bob will therefore each maintain two keychains, one for Alice to track the addresses she is going to post messages to, and one for Alice to anticipate which addresses Bob will use to write messages for her to read.

The main technical reference is the protocol verification script, since this code is just an implementation of that protocol. 

### Formal Verification

A verification of a (simplified) version of the protocol is available in [`protocol-verification.vp`](protocol-verification.vp), which defines a [Verifpal script](https://verifpal.com/). In this simplified model we do not bother to encrypt any messages between participants, and rather than authenticating ephemeral public keys we use Verifpal features to "guard" them against tampering by the attacker. We feel that this simplification is justified because for any realistic implementation of a messaging protocol the users (principals) would use AEAD to secure messages, and the public keys could simply be contained within encrypted messages (allowing them to "piggy back" on the pre-existing authentication mechanisms of the AEAD protocol). 

You can explore what happens if we do not guard the public keys by removing the guards from the protocol and re-running the script (essentially, the attacker can force the principal to post to the "wrong" address). 

However, one fringe benefit of this is that we can be confident that the protocol retains its security properties even when the attacker can see the ephemeral public keys.