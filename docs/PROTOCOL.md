# Parley protocol and threat model

## Keys

| Key | Type | Lifetime | Where the private half lives |
|---|---|---|---|
| Signing key `SK` | Ed25519 | account | vault |
| Identity key `IK` | X25519, signed by `SK` | account | vault |
| Signed pre-key `SPK` | X25519, signed by `SK` | rotated weekly, kept 30 days | vault |
| One-time pre-keys `OPK` | X25519 | single use | vault (deleted on use) |
| Ratchet keys | X25519 | one per direction change | ratchet state (vault) |

Every signature is domain-separated:

- `IK` is signed over `"Parley/identity-dh/v1" ‖ IK`.
- `SPK` is signed over `"Parley/signed-prekey/v1" ‖ u32(id) ‖ SPK`, so the server can't relabel a key id.

Ed25519 verification is strict (RFC 8032, ZIP-215 disabled), and small-order public keys are rejected.

## Authentication

1. `POST /api/auth/challenge {purpose, handle}` returns a 256-bit random nonce. It is valid for 2 minutes and can be used once.
2. The client signs `"Parley/auth/v1\n" ‖ purpose ‖ "\n" ‖ handle ‖ "\n" ‖ nonce` with `SK`.
3. `register` uploads the public keys and the signature, and the server verifies every signature. `login` sends only the signature.
4. The server returns a random 256-bit bearer token. It stores only the token's SHA-256 hash, and the client keeps the token only in memory.

The challenge is deleted the moment it is used, whether the attempt succeeds or not. Authentication endpoints are rate-limited per IP.

## X3DH

The initiator `A` fetches `B`'s bundle. The server hands out each one-time pre-key at most once: it deletes the key with an atomic `DELETE … RETURNING`. `A` then verifies both signatures and computes:

```
DH1 = X25519(IK_A, SPK_B)    DH2 = X25519(EK_A, IK_B)
DH3 = X25519(EK_A, SPK_B)    DH4 = X25519(EK_A, OPK_B)   (if an OPK was available)
SK  = HKDF-SHA256(ikm = 0xFF×32 ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4], salt = 0×32, info = "Parley/X3DH/v1")
AD  = "Parley/AD/v1" ‖ SK_A ‖ IK_A ‖ SK_B ‖ IK_B
```

`AD` is bound into the AEAD of every message in the session. An all-zero X25519 output is rejected.

## Double Ratchet

Parley follows the Signal specification, with these choices:

- `KDF_RK(rk, dh) = HKDF-SHA256(ikm = dh, salt = rk, info = "Parley/Ratchet/root/v1")`, which gives the new root key and a chain key.
- `KDF_CK(ck)`: the message key is `HMAC-SHA256(ck, 0x01)` and the next chain key is `HMAC-SHA256(ck, 0x02)`.
- Encryption uses AES-256-GCM. The key and nonce are `HKDF(mk, info = "Parley/Ratchet/message/v1")`, split as 32 bytes of key and 12 bytes of nonce. A deterministic nonce is safe here because every message key is used exactly once.
- The associated data is `AD ‖ header`. The header is the 40 bytes `ratchetPub(32) ‖ u32 pn ‖ u32 n`.
- Plaintext is padded to 128-byte blocks with ISO/IEC 7816-4 padding before encryption.
- Out-of-order messages are handled by caching skipped message keys. At most `MAX_SKIP = 1000` keys may be derived to reach one message, and at most 2,000 are cached in total; the oldest are evicted first.
- Every operation is pure: it takes a state and returns a new one. A message that fails to authenticate leaves the stored state untouched.

### Sessions

A session is identified by the initiator's ephemeral key `EK_A`. Until the initiator decrypts a reply, every message it sends carries the X3DH header, so the responder can set up the session even if the first message is lost.

Each peer keeps up to 5 sessions. The client sends on the most recently successful one and tries incoming messages against each in turn. If both people start a conversation at the same moment, they converge on a single session after one round trip, as an end-to-end test checks.

## Envelope (wire format)

```json
{
  "v": 1,
  "preKey": { "signingKey": "…", "identityKey": "…", "identityKeySignature": "…",
              "ephemeralKey": "…", "signedPreKeyId": 1, "oneTimePreKeyId": 42 },
  "header": "<base64, 40 bytes>",
  "ciphertext": "<base64>"
}
```

The server checks the envelope's structure and size, then treats it as opaque.

Inside the encryption, the payload is JSON in one of three forms:

- `{k:"text", id, body, ts}`
- `{k:"receipt", status, ids}`
- `{k:"typing", on}`

Receipts and typing indicators are ratchet messages like any other. This is why the chain counters in the inspector can skip numbers.

## Transport

- **Relay (WebSocket `/api/ws`).**
  - The client authenticates with its token in the first frame, so the token never appears in a URL.
  - Each account has one live connection; a new one replaces the old.
  - Envelopes go into the mailbox and are deleted when the recipient sends `ack`. Only the recipient can acknowledge a message.
  - Transient envelopes, used for typing indicators, are forwarded only if the recipient is online and are never stored.
- **Direct (WebRTC).**
  - Both peers create a pre-negotiated data channel (`id: 0`).
  - Offers and ICE candidates travel through the relay.
  - Offer collisions are resolved by user id: the peer with the higher id is "polite".
  - A link that hasn't opened within 15 seconds is dropped, the client falls back to the relay, and it waits 60 seconds before trying again.
- **Idempotency.** The client keeps a hash of the last 2,000 envelopes it processed. A redelivery, whether from a lost acknowledgement or a resend after reconnecting, is acknowledged and otherwise ignored.

## Local storage

- **The vault.** Everything is stored in IndexedDB as `{iv, AES-256-GCM(plaintext, AD = "parley-vault/v1:" ‖ recordName)}`. The key comes from PBKDF2-SHA256 (600,000 iterations, 16-byte salt) and is a non-extractable WebCrypto key held only in memory.
- **Atomic writes.** Writes that must happen together, such as a ratchet state and the message it produced, are encrypted first and then committed in a single IndexedDB transaction.
- **Backups.** A backup is the raw encrypted vault, so it is exactly as strong as the passphrase.
- **One tab at a time.** A Web Lock ensures only one tab uses the keys at a time. Two tabs advancing the same ratchet would break every session.

## Threat model

**Protected against:**

- **A passive or malicious relay server.** It never sees plaintext, private keys or the content of receipts and typing indicators.
- **Key substitution by the server.** Clients verify bundle signatures and pin identities on first use. A changed identity disables sending until the user acknowledges it, and safety numbers let users rule out a man in the middle.
- **Network attackers.** They face TLS in deployment, then the end-to-end AEAD. A MITM on the WebRTC signalling only ever sees ciphertext.
- **Replay and tampering.**
  - Every message is authenticated with AES-GCM over a header bound to the session.
  - A one-time pre-key can only be used once.
  - A duplicate message key fails to decrypt.
- **Compromise of a single message key.** Forward secrecy protects the others.
- **Compromise of a ratchet state.** It heals after the next round trip, which is post-compromise security, tested in `ratchet.test.ts`.
- **Theft of the browser profile while it is locked.** The vault requires the passphrase.

**Not protected against:**

- **A compromised client.** Malware on the device, or a server that serves malicious JavaScript, can read everything.
- **Traffic analysis.** The relay learns who talks to whom, when and how much (lengths are padded to 128 bytes). A direct link reveals each peer's IP address to the other, which is why links are only accepted from contacts and relay-only mode exists.
- **Users who skip verification.** Trust on first use is only as good as the first contact.
- **One-time pre-key exhaustion.** Someone fetching bundles in bulk can use them all up. Bundle fetches are rate-limited, and once the one-time keys run out X3DH falls back to the signed pre-key alone, which is weaker against replay.
