# A Fully Anonymous (Direct) Messaging Protocol

This document describes a protocol for 2-party messaging which provides: (1) anonymity for both the sender *and the recipient* of a message, (2) no evidence of participation in the service (no accounts), and (3) where the client-side key-management requirements scale linearly with the number of conversations held. This protocol could be easily combined with other existing anonymity protocols and systems (such as Tor), and existing end-to-end encryption schemes such as the Signal protocol. The basic idea is that the participants in a conversation deposit each of their messages in a new, (seemingly) random mailbox in a very, very large post office (32 bytes, for instance). The "address" of each mailbox is unlinkable from any of the previous mailboxes. Only the participants in a conversation can determine which mailboxes will be used next. We accomplish this by using a slight variation of the double ratchet algorithm (employed by the Signal protocol), which offers desirable security properties (described below).

For an overview of the proof-of-concept code, see the [readme](./README.md). For a verification of the protocol described here (using [Verifpal](https://verifpal.com/)) see this [script](./protocol-verification.vp).

### Motivation 

Many people mistakenly conflate the use of a pseudonym with anonymity. For example, authors frequently will write under a pen name (such as Richard Bachmann/Steven King), and almost as frequently those pen names are unmasked. Similar stories exist in the digital world, such as the [de-anonymization of bitcoin wallets](https://www.schneier.com/blog/archives/2022/04/de-anonymizing-bitcoin.html). The weakness of a pseudonym is that it is re-used: once a real world identity is linked to the pseudonym all activity performed under the pseudonym can be mapped back to the true identity. What is required is the *unlinkability* property: successive message "addresses" cannot be linked. On paper, the solution is simple: always use random identities/addresses. This can work in public settings, such as social media, where the content is available for all to see. Most academic research into "formal" privacy (deriving from [mix networks](https://en.wikipedia.org/wiki/Mix_network) or [dc networks](https://en.wikipedia.org/wiki/Dining_cryptographers_problem)) also assumes that at least some of the message (meta)data will be public (even if the content is encrypted). 

Unfortunately, the situation becomes complicated when we want to ensure both privacy and anonymity because the participants in a conversation need to coordinate their random addresses somehow. For the simplicity, we will name these participants Alice and Bob. We will also assume that the parties can employ end-to-end encryption to protect their messages. There are two seemingly-obvious solutions that we could try:

 1. Alice and Bob could meet ahead of time "offline" and agree on an initial address (or rather, one random initial address each). Whenever Alice wants to message Bob (or vice versa) she generates a random address to use next time, and encrypts it with the rest of her message to Bob. Realistically, they'd probably need to generate several addresses to deal with out-of-order messages.

 2. Just as in case 1, Alice and Bob coordinate a random initial address each. Then, whenever Bob wants to message Alice (or vice versa) he calculates a cryptographically suitable hash of his first address to use as his next address.

 
The problem with both of these simple schemes is that they lack post-compromise security. If an attacker can compromise one of the messages, then they can compromise the rest of the messages moving forward. Luckily, a "self-healing" protocol for messaging already exists to handle encryption keys: the Signal protocol (or more specifically, the double-ratchet algorithm). In a nutshell, the double-ratchet algorithm is similar to the second scheme described above, except with "fresh" randomness mixed in periodically to kick an attacker out after a few messages have been sent. A slight modification of the double ratchet algorithm makes it suitable for use in generating unlinkable addresses.

### Overview

We describe a protocol to generate random addresses suitable for use with a messaging protocol. The goal, at a high level, is not just to **provide message-level anonymity** but to have **no way to identify someone as being a user** of the service. This protocol is currently only specified for two parties, Alice and Bob. We assume that the message contents are secured using end to end encryption. Alice (and ditto for Bob) maintains two keyrings/address books, one for her own future address(es) and one for Bob's future address(es). Each of these is a "flavored" version of the double ratchet. A simple server is required, but all it needs to do is act as a key-value store of addresses (keys) and messages (values). (In theory, one could construct a distributed network of servers coordinated with something like a gossip protocol, but this is beyond the scope of this document.)

### Comparison to Existing Work 

The primary difference between this work and what we are aware of in the literature is anonymity for the recipient of a message. As mentioned above, most anonymous protocols focus solely on sender anonymity. However, our protocol should be able to "sit on top of" most existing anonymity protocols due to the intentionally simple requirements on the server. This protocol should not be viewed as "competing" with something like Tor or Signal, but rather a mechanism that could be deployed in conjunction with existing systems to provide additional privacy.

* [Mix networks](https://en.wikipedia.org/wiki/Mix_network) (the theoretical basis for systems like Tor) hide the source of a message (when working properly), but have no built in protection for message recipients. Generally, mix networks are intended for transport level anonymity and would probably require the use of some "mailbox" server at the end of a chain. That server would still know that Bob is a user of the system and how many messages Bob is receiving, even if it can't identify who is sending them.

* [DC networks](https://en.wikipedia.org/wiki/Dining_cryptographers_problem) technically offer both "unconditional" sender and receiver anonymity, although in an impractical way. Because sender anonymity seems relatively "common" we will focus on the receiver side: a DC net broadcasts the message to every participant in the network. Clearly, to preserve privacy we would need to encrypt the messages, so everyone receives the message but only the intended party can decrypt it. For any sufficiently large or "talkative" network trying to decrypt and manage all of these messages would quickly prove infeasible. Furthermore, to do this requires participants to publish public keys, thereby identifying (at least with a pseudonym) the participants in the network. There are other significant barriers to practical implementation. First is the issue of internal sabotage by a malicious actor ("[cheating players](https://link.springer.com/chapter/10.1007/978-3-540-24676-3_27)"), which can be mitigated at the cost of extra computational work. Second is a key-management problem: every participant needs to securely negotiate and maintain a pairwise shared secret with every other participant in the network (which grows at O(n^2)) even if they don't intend on messaging that participant, which again limits the practical size of any network. 

* The Signal app offers the [sealed senders](https://signal.org/blog/sealed-sender/) feature. Obviously, this can only hide the sender of the message.

## Technical Details

#### Requirements on the Client and Server

A client implementation...

- must follow the protocol
- must implement a suitable form of AEAD to protect message contents
- should maintain a keyring/address book for multiple chats 
- should implement and document a retention policy for messages, keys, addresses, etc.
- should encrypt the locally stored files

A server implementation...

- must support at a minimum a storage mechanism that can associate an arbitrary byte-string address to arbitrary byte-string messages
- must **not** allow users to query for addresses currently in use. 
- should implement and document a retention policy for deposited messages. 
- should document a priority policy for when two messages conflict/collide/share an address. (This risk should be minimal given 32 byte addresses.)
- should not log addresses or messages, outside of debug or test settings.
- should not log metadata, such as IP addresses

### Threat Model / Assumptions

We assume the following*:

- (Required for security) **The two parties in the conversation have some way to safely exchange initial keying material** (such as an in person meeting). The primary limitation of this protocol is the bootstrapping problem: how can the participants in a conversation safely perform their initial key exchange? This is very difficult without a pre-existing address. In a system like Signal's, they have a trusted "public" address (their phone numbers) to facilitate the initial (and ongoing) communication. No such equivalent exists for this system. Practically, a simple way to do this might be to scan QR codes or exchange that information using other "local" peer-to-peer methods (such as Bluetooth or NFE). However, depending on the threat model of the participants, this may or may not be feasible (if you're photographed exchanging contact information then it probably doesn't matter if your online communications are anonymous!).
- (Required for security) **The two parties have some way to hide their communications metadata** (IP addresses or whatnot). This protocol does NOT provide "metadata anonymity" (i.e. IP addresses and such), which is outside the scope of this system. In theory, that form of anonymity should be available using something like TOR, since this system only needs some "blind" server to act as a middleman.
- (Usability, not security) **The middleman/dropbox server does not alter the addresses.** (We say this isn't required for security given the Verifpal script's security against an "Active" attacker.) By the protocol, the middleman server should not know the identity of anyone depositing messages with it, even though it sees all messages. Therefore, the implications of this assumption depend on how it is violated. If the compromised server tampers with the addresses at random (such as in the case of a network error, hardware failure, random bitflipping, etc.) then the primary implication is dropped messages. If the compromised server instead intentionally alters addresses, such as swapping addresses between messages, then recipients will be delivered the wrong message. If message contents are <u>protected by a suitable AEAD algorithm this should not compromise security</u>.
- (Usability, not security) **A server exists that can be trusted not to tamper with the message content.** (We say this isn't required for security given the Verifpal script's security against an "Active" attacker.) A compromised server should not compromise security <u>so long as the participants use a suitable AEAD scheme to protect their uploaded messages</u>. 

*Note that the assumptions in our verification script have a more technical definition, you can check the Verifpal documentation for an "active" attacker for those details.

### Other Potential Issues or Limitations

- There is a theoretical risk of address collision (which cannot practically be eliminated from the protocol), since of course random oracles are not possible in the real world. A suitably large address space (32 bytes) should minimize this risk.
- The server/middleman is open to abuse (particularly in the form of stuffing or DOS-style attacks) against addresses. In theory, with a large enough address space, someone spamming random addresses with garbage messages should have a near-zero probability of overwriting or interfering with an actual message **so long as the attacker cannot see which addresses are in use**. 

### Cryptographic Primitives Required

- Diffie Hellman Key Exchange
- HKDF

### Differences from Signal's Double Ratchet Algorithm

The core technical difference is that we have to maintain 2 keychains (for a 2 party conversation), where the original algorithm only needs 1. This is because each party needs to maintain a keychain for their own address and the "anticipated" address of their counterparty. This has a few minor knock-on effects for things like out of order messages, or delayed delivery (i.e. the implementation has to take care to avoid minor synchronization issues from throwing the chat into an error state). These issues can be addressed by implementing a "look-ahead" system: because one participant repeatedly sending messages has addresses that are predictable by their counterparty, that counterparty can maintain some local state of the next N predicted addresses. 
