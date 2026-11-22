//! hello-crypto — cryptographic layer for HelloVPN.
//!
//! # What this crate provides
//!
//! * [`KeyPair`] — X25519 keypair management with zeroize-on-drop.
//! * [`ReplayWindow`] — 64-slot sliding bitmap for sequence-number deduplication.
//! * [`SessionCipher`] — wraps snow's `StatelessTransportState` for data-channel
//!   ChaCha20-Poly1305 AEAD with explicit sequence-number nonces.
//!
//! # What this crate does NOT do
//!
//! * It does not implement any cryptographic algorithm from scratch.
//! * All primitives come from `snow` (which uses `ring` internally).

pub mod keypair;
pub mod replay;
pub mod cipher;

pub use keypair::KeyPair;
pub use replay::ReplayWindow;
pub use cipher::SessionCipher;
