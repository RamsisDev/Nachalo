//! Nachalo Channel v1: what two peers run after a Nachalo handshake, specified in
//! `spec/channel.md`. It is not part of the Nachalo v0 specification and has not been audited.
//!
//! - Every key comes from the handshake's `export(label)` through [`Secrets::derive`], so the
//!   channel is bound to that one transcript.
//! - Each direction runs a symmetric ratchet: the key of message `n` comes from the chain key
//!   `ck_n`, which is erased once `ck_(n+1)` is derived. Stealing today's state does not open
//!   yesterday's frames.
//! - Frames are exactly [`FRAME_SMALL`] or [`FRAME_LARGE`] bytes, so the relay does not learn
//!   message lengths. The header is authenticated as associated data together with the peer id.
//! - Relay topics rotate every UTC day and come from a secret seed per direction.
//! - A receiver keeps at most [`MAX_SKIPPED`] keys of frames that have not arrived yet, for
//!   [`SKIPPED_TTL`] seconds, and rejects a counter it already used.
//! - [`Channel::seal_state`] serializes the whole state encrypted under a store key, so the host
//!   language only ever holds an opaque blob.
//!
//! The crate is sans-IO: frames are byte strings the application carries, and time is passed in.

use std::collections::BTreeMap;

use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// A 32-byte symmetric key.
pub type Key = [u8; 32];

/// Version byte of every frame and of the sealed state.
pub const VERSION: u8 = 1;
/// Length of the authenticated header: version, kind, epoch and counter.
pub const HEADER_LEN: usize = 14;
/// Length of the Poly1305 tag.
pub const TAG_LEN: usize = 16;
/// The small frame size, in bytes.
pub const FRAME_SMALL: usize = 512;
/// The large frame size, in bytes.
pub const FRAME_LARGE: usize = 2048;
/// Largest body a small frame carries.
pub const MAX_BODY_SMALL: usize = FRAME_SMALL - HEADER_LEN - TAG_LEN - 2;
/// Largest body a large frame carries.
pub const MAX_BODY: usize = FRAME_LARGE - HEADER_LEN - TAG_LEN - 2;
/// Most keys of not-yet-arrived frames a receiver keeps per direction.
pub const MAX_SKIPPED: usize = 64;
/// Most a counter may jump ahead of the next expected one.
pub const MAX_SKIP: u64 = MAX_SKIPPED as u64;
/// How long a skipped key is kept, in seconds.
pub const SKIPPED_TTL: u64 = 7 * 86_400;
/// Length of a relay topic.
pub const TOPIC_LEN: usize = 34;
/// Longest peer id the channel binds.
pub const MAX_PEER_ID: usize = 64;

/// Labels passed to the handshake's `export`, one per use.
pub mod labels {
    /// Initial chain key from initiator to responder.
    pub const CHAIN_I2R: &[u8] = b"hermes-nachalo/1 chain i2r";
    /// Initial chain key from responder to initiator.
    pub const CHAIN_R2I: &[u8] = b"hermes-nachalo/1 chain r2i";
    /// Topic seed from initiator to responder.
    pub const TOPIC_I2R: &[u8] = b"hermes-nachalo/1 topic i2r";
    /// Topic seed from responder to initiator.
    pub const TOPIC_R2I: &[u8] = b"hermes-nachalo/1 topic r2i";
    /// Root for the hybrid re-key (v1.1).
    pub const ROOT: &[u8] = b"hermes-nachalo/1 root";
}

const INFO_MSG: &[u8] = b"hermes-nachalo/1 msg";
const INFO_CHAIN: &[u8] = b"hermes-nachalo/1 chain";
const INFO_EPOCH: &[u8] = b"hermes-nachalo/1 epoch";
const INFO_STATE: &[u8] = b"hermes-nachalo/1 state";
const STATE_NONCE_LEN: usize = 12;

/// Why a step failed. A frame that does not authenticate says nothing more than `Rejected`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Malformed frame, wrong size or version, or a tag that does not verify.
    Rejected,
    /// A counter this side already opened, or whose key has expired.
    Replay,
    /// A counter more than [`MAX_SKIP`] ahead of the next expected one.
    TooFarAhead,
    /// A body longer than [`MAX_BODY`].
    TooLarge,
    /// The send counter ran out.
    Exhausted,
    /// Sealed state that does not open with this key and peer id, or a bad store key or peer id.
    BadState,
    /// The OS random generator failed.
    Rng,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}

/// Which side of the handshake this device played.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// A: sends on `i2r`, receives on `r2i`.
    Initiator,
    /// B: sends on `r2i`, receives on `i2r`.
    Responder,
}

/// What a frame carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Application data.
    Data,
    /// Acknowledgement of received message ids.
    Ack,
    /// Hybrid re-key (v1.1).
    Rekey,
    /// The sender revoked the pairing.
    Close,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Kind::Data => 1,
            Kind::Ack => 2,
            Kind::Rekey => 3,
            Kind::Close => 4,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Kind::Data),
            2 => Some(Kind::Ack),
            3 => Some(Kind::Rekey),
            4 => Some(Kind::Close),
            _ => None,
        }
    }
}

/// The key material a channel starts from, all from the handshake's `export`.
pub struct Secrets {
    chain_i2r: Zeroizing<Key>,
    chain_r2i: Zeroizing<Key>,
    topic_i2r: Zeroizing<Key>,
    topic_r2i: Zeroizing<Key>,
    root: Zeroizing<Key>,
}

impl Secrets {
    /// Derives every key from `export`, the established handshake's `export(label)`.
    pub fn derive(export: impl Fn(&[u8]) -> Zeroizing<Key>) -> Self {
        Secrets {
            chain_i2r: export(labels::CHAIN_I2R),
            chain_r2i: export(labels::CHAIN_R2I),
            topic_i2r: export(labels::TOPIC_I2R),
            topic_r2i: export(labels::TOPIC_R2I),
            root: export(labels::ROOT),
        }
    }
}

/// An opened frame.
#[derive(Debug)]
pub struct Opened {
    /// What it carries.
    pub kind: Kind,
    /// The topic epoch the sender wrote in the header.
    pub epoch: u32,
    /// Its counter in the sender's ratchet.
    pub counter: u64,
    /// The body, without padding.
    pub body: Zeroizing<Vec<u8>>,
}

struct Skipped {
    key: Zeroizing<Key>,
    stored_at: u64,
}

/// One side of an established channel.
pub struct Channel {
    role: Role,
    peer_id: Vec<u8>,
    send_chain: Zeroizing<Key>,
    send_next: u64,
    recv_chain: Zeroizing<Key>,
    recv_next: u64,
    skipped: BTreeMap<u64, Skipped>,
    topic_send: Zeroizing<Key>,
    topic_recv: Zeroizing<Key>,
    root: Zeroizing<Key>,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("role", &self.role)
            .field("send_next", &self.send_next)
            .field("recv_next", &self.recv_next)
            .field("skipped", &self.skipped.len())
            .finish_non_exhaustive()
    }
}

impl Channel {
    /// A fresh channel for `role`, bound to `peer_id` (public, equal on both sides, at most
    /// [`MAX_PEER_ID`] bytes).
    pub fn new(role: Role, secrets: &Secrets, peer_id: &[u8]) -> Result<Self, Error> {
        if peer_id.is_empty() || peer_id.len() > MAX_PEER_ID {
            return Err(Error::BadState);
        }
        let (send, recv, topic_send, topic_recv) = match role {
            Role::Initiator => (
                &secrets.chain_i2r,
                &secrets.chain_r2i,
                &secrets.topic_i2r,
                &secrets.topic_r2i,
            ),
            Role::Responder => (
                &secrets.chain_r2i,
                &secrets.chain_i2r,
                &secrets.topic_r2i,
                &secrets.topic_i2r,
            ),
        };
        Ok(Channel {
            role,
            peer_id: peer_id.to_vec(),
            send_chain: send.clone(),
            send_next: 0,
            recv_chain: recv.clone(),
            recv_next: 0,
            skipped: BTreeMap::new(),
            topic_send: topic_send.clone(),
            topic_recv: topic_recv.clone(),
            root: secrets.root.clone(),
        })
    }

    /// Which side this device played.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The peer id this channel is bound to.
    pub fn peer_id(&self) -> &[u8] {
        &self.peer_id
    }

    /// Frames sealed so far.
    pub fn sent(&self) -> u64 {
        self.send_next
    }

    /// The next counter this side expects from the peer.
    pub fn received(&self) -> u64 {
        self.recv_next
    }

    /// The topic this side publishes to on UTC day `epoch`.
    pub fn send_topic(&self, epoch: u32) -> String {
        topic(&self.topic_send, epoch)
    }

    /// The topic this side reads on UTC day `epoch`. Subscribe to `epoch - 1`, `epoch` and
    /// `epoch + 1` to absorb clock skew.
    pub fn recv_topic(&self, epoch: u32) -> String {
        topic(&self.topic_recv, epoch)
    }

    /// Seals `body` into one frame of [`FRAME_SMALL`] bytes if it fits, else [`FRAME_LARGE`].
    /// `now_unix` sets the epoch written in the header.
    pub fn seal(&mut self, kind: Kind, body: &[u8], now_unix: u64) -> Result<Vec<u8>, Error> {
        let size = if body.len() <= MAX_BODY_SMALL {
            FRAME_SMALL
        } else if body.len() <= MAX_BODY {
            FRAME_LARGE
        } else {
            return Err(Error::TooLarge);
        };
        let counter = self.send_next;
        let next = counter.checked_add(1).ok_or(Error::Exhausted)?;
        let message_key = derive(&self.send_chain, INFO_MSG);
        let next_chain = derive(&self.send_chain, INFO_CHAIN);

        let mut frame = Vec::with_capacity(size);
        frame.push(VERSION);
        frame.push(kind.byte());
        frame.extend_from_slice(&epoch_of(now_unix).to_be_bytes());
        frame.extend_from_slice(&counter.to_be_bytes());

        let mut plaintext = Zeroizing::new(vec![0u8; size - HEADER_LEN - TAG_LEN]);
        let len = u16::try_from(body.len()).map_err(|_| Error::TooLarge)?;
        plaintext[..2].copy_from_slice(&len.to_be_bytes());
        plaintext[2..2 + body.len()].copy_from_slice(body);

        let aad = self.aad(&frame);
        let tag = ChaCha20Poly1305::new(&(*message_key).into())
            .encrypt_inout_detached(
                &nonce(counter).into(),
                &aad,
                plaintext.as_mut_slice().into(),
            )
            .map_err(|_| Error::TooLarge)?;
        frame.extend_from_slice(&plaintext);
        frame.extend_from_slice(&tag);

        self.send_chain = next_chain;
        self.send_next = next;
        Ok(frame)
    }

    /// Opens one frame from the peer. Nothing changes unless the frame authenticates, so a
    /// forged or replayed frame leaves the channel as it was.
    pub fn open(&mut self, frame: &[u8], now_unix: u64) -> Result<Opened, Error> {
        self.expire_skipped(now_unix);
        if frame.len() != FRAME_SMALL && frame.len() != FRAME_LARGE {
            return Err(Error::Rejected);
        }
        let (header, rest) = frame.split_at(HEADER_LEN);
        if header[0] != VERSION {
            return Err(Error::Rejected);
        }
        let kind = Kind::from_byte(header[1]).ok_or(Error::Rejected)?;
        let epoch = u32::from_be_bytes(header[2..6].try_into().map_err(|_| Error::Rejected)?);
        let counter = u64::from_be_bytes(header[6..14].try_into().map_err(|_| Error::Rejected)?);
        let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
        let aad = self.aad(header);

        if counter < self.recv_next {
            let skipped = self.skipped.get(&counter).ok_or(Error::Replay)?;
            let body = decrypt(&skipped.key, counter, &aad, ciphertext, tag)?;
            self.skipped.remove(&counter);
            return Ok(Opened {
                kind,
                epoch,
                counter,
                body,
            });
        }
        if counter - self.recv_next > MAX_SKIP {
            return Err(Error::TooFarAhead);
        }

        let mut chain = self.recv_chain.clone();
        let mut passed = Vec::new();
        for skipped in self.recv_next..counter {
            passed.push((skipped, derive(&chain, INFO_MSG)));
            chain = derive(&chain, INFO_CHAIN);
        }
        let message_key = derive(&chain, INFO_MSG);
        let body = decrypt(&message_key, counter, &aad, ciphertext, tag)?;

        self.recv_chain = derive(&chain, INFO_CHAIN);
        self.recv_next = counter + 1;
        for (skipped, key) in passed {
            self.skipped.insert(
                skipped,
                Skipped {
                    key,
                    stored_at: now_unix,
                },
            );
        }
        while self.skipped.len() > MAX_SKIPPED {
            self.skipped.pop_first();
        }
        Ok(Opened {
            kind,
            epoch,
            counter,
            body,
        })
    }

    /// The whole state, encrypted under `store_key` and bound to the peer id. Store this blob;
    /// it is the only form in which the state leaves the crate.
    pub fn seal_state(&self, store_key: &Key) -> Result<Vec<u8>, Error> {
        let mut plain = Zeroizing::new(Vec::with_capacity(256 + self.skipped.len() * 48));
        plain.push(VERSION);
        plain.push(match self.role {
            Role::Initiator => 0,
            Role::Responder => 1,
        });
        plain.push(self.peer_id.len() as u8);
        plain.extend_from_slice(&self.peer_id);
        plain.extend_from_slice(self.send_chain.as_ref());
        plain.extend_from_slice(&self.send_next.to_be_bytes());
        plain.extend_from_slice(self.recv_chain.as_ref());
        plain.extend_from_slice(&self.recv_next.to_be_bytes());
        plain.extend_from_slice(self.topic_send.as_ref());
        plain.extend_from_slice(self.topic_recv.as_ref());
        plain.extend_from_slice(self.root.as_ref());
        plain.push(self.skipped.len() as u8);
        for (counter, skipped) in &self.skipped {
            plain.extend_from_slice(&counter.to_be_bytes());
            plain.extend_from_slice(skipped.key.as_ref());
            plain.extend_from_slice(&skipped.stored_at.to_be_bytes());
        }

        let mut nonce = [0u8; STATE_NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| Error::Rng)?;
        let aad = lv_cat(&[INFO_STATE, &self.peer_id]);
        let mut sealed = plain.to_vec();
        let tag = ChaCha20Poly1305::new(&(*store_key).into())
            .encrypt_inout_detached(&nonce.into(), &aad, sealed.as_mut_slice().into())
            .map_err(|_| Error::BadState)?;
        let mut out = Vec::with_capacity(1 + STATE_NONCE_LEN + sealed.len() + TAG_LEN);
        out.push(VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Restores a channel from [`seal_state`](Self::seal_state). Fails with `BadState` unless the
    /// blob was sealed under `store_key` for `peer_id`.
    pub fn open_state(blob: &[u8], store_key: &Key, peer_id: &[u8]) -> Result<Self, Error> {
        if blob.len() < 1 + STATE_NONCE_LEN + TAG_LEN || blob[0] != VERSION {
            return Err(Error::BadState);
        }
        let nonce: [u8; STATE_NONCE_LEN] = blob[1..1 + STATE_NONCE_LEN]
            .try_into()
            .map_err(|_| Error::BadState)?;
        let body = &blob[1 + STATE_NONCE_LEN..];
        let (ciphertext, tag) = body.split_at(body.len() - TAG_LEN);
        let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| Error::BadState)?;
        let aad = lv_cat(&[INFO_STATE, peer_id]);
        let mut plain = Zeroizing::new(ciphertext.to_vec());
        ChaCha20Poly1305::new(&(*store_key).into())
            .decrypt_inout_detached(
                &nonce.into(),
                &aad,
                plain.as_mut_slice().into(),
                &tag.into(),
            )
            .map_err(|_| Error::BadState)?;

        let mut reader = Reader(&plain);
        if reader.byte()? != VERSION {
            return Err(Error::BadState);
        }
        let role = match reader.byte()? {
            0 => Role::Initiator,
            1 => Role::Responder,
            _ => return Err(Error::BadState),
        };
        let id_len = reader.byte()? as usize;
        if reader.take(id_len)? != peer_id {
            return Err(Error::BadState);
        }
        let send_chain = reader.key()?;
        let send_next = reader.u64()?;
        let recv_chain = reader.key()?;
        let recv_next = reader.u64()?;
        let topic_send = reader.key()?;
        let topic_recv = reader.key()?;
        let root = reader.key()?;
        let count = reader.byte()? as usize;
        if count > MAX_SKIPPED {
            return Err(Error::BadState);
        }
        let mut skipped = BTreeMap::new();
        for _ in 0..count {
            let counter = reader.u64()?;
            let key = reader.key()?;
            let stored_at = reader.u64()?;
            skipped.insert(counter, Skipped { key, stored_at });
        }
        if !reader.0.is_empty() {
            return Err(Error::BadState);
        }
        Ok(Channel {
            role,
            peer_id: peer_id.to_vec(),
            send_chain,
            send_next,
            recv_chain,
            recv_next,
            skipped,
            topic_send,
            topic_recv,
            root,
        })
    }

    fn aad(&self, header: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(HEADER_LEN + self.peer_id.len());
        aad.extend_from_slice(&header[..HEADER_LEN]);
        aad.extend_from_slice(&self.peer_id);
        aad
    }

    fn expire_skipped(&mut self, now_unix: u64) {
        self.skipped
            .retain(|_, skipped| now_unix.saturating_sub(skipped.stored_at) < SKIPPED_TTL);
    }
}

/// The UTC day of a Unix time, which names the relay topics.
pub fn epoch_of(now_unix: u64) -> u32 {
    u32::try_from(now_unix / 86_400).unwrap_or(u32::MAX)
}

/// `lv_cat` from the Nachalo specification: each part as its LEB128 length, then its bytes.
pub fn lv_cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        let mut len = part.len();
        loop {
            let byte = (len & 0x7f) as u8;
            len >>= 7;
            if len == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out.extend_from_slice(part);
    }
    out
}

fn derive(key: &Key, info: &[u8]) -> Zeroizing<Key> {
    hkdf::<32>(key, info)
}

fn hkdf<const N: usize>(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0u8; N]);
    Hkdf::<Sha256>::new(Some(&[]), ikm)
        .expand(info, out.as_mut())
        .expect("HKDF output length is a compile-time constant within limits");
    out
}

fn topic(seed: &Key, epoch: u32) -> String {
    let bytes = hkdf::<24>(seed, &lv_cat(&[INFO_EPOCH, &epoch.to_be_bytes()]));
    let mut out = String::with_capacity(TOPIC_LEN);
    out.push_str("nh");
    out.push_str(&base64url(bytes.as_ref()));
    out
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn decrypt(
    key: &Key,
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let tag: [u8; TAG_LEN] = tag.try_into().map_err(|_| Error::Rejected)?;
    let mut plain = Zeroizing::new(ciphertext.to_vec());
    ChaCha20Poly1305::new(&(*key).into())
        .decrypt_inout_detached(
            &nonce(counter).into(),
            aad,
            plain.as_mut_slice().into(),
            &tag.into(),
        )
        .map_err(|_| Error::Rejected)?;
    let len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
    if len > plain.len() - 2 {
        return Err(Error::Rejected);
    }
    Ok(Zeroizing::new(plain[2..2 + len].to_vec()))
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::BadState);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::BadState)?,
        ))
    }

    fn key(&mut self) -> Result<Zeroizing<Key>, Error> {
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(self.take(32)?);
        Ok(key)
    }
}

#[cfg(test)]
mod tests;
