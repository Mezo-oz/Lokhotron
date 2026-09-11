//! The synthetic control probe's wire format — **keyed**.
//!
//! This is the one datagram layout both ends of the UDP delta agree on, so it lives in one
//! crate instead of being spelled twice. ECHO.md §2 allows this probe an explicit header
//! (it is openly synthetic and never dressed as a real transport), so the header can carry
//! authentication that a real-transport probe could not.
//!
//! # What the key buys
//!
//! The MVP format (`[nonce][marker][known payload]`, payload a *public* function of the
//! marker) had two holes that only show up against a live adversary:
//!
//! 1. **A rewrite of the identifying header read as a drop.** If a middlebox rewrote the
//!    marker, the echo stopped being recognizable and the run reported
//!    `silent_drop_from_segment` — a fabricated block on a path that actually delivered.
//! 2. **Delivery could be faked.** Anything on the path could echo the datagram back
//!    itself, and the probe would score it as arrived. A censor that drops traffic and
//!    reflects the probe reads as `ok`.
//!
//! Both close with one mechanism. Every datagram carries a **32-byte keyed payload**
//! derived from `(nonce, marker, session)` — so it identifies itself even when its header
//! is destroyed — and a **leg tag** that is domain-separated between request and response,
//! so only the far end (which holds the key) can produce something the probe scores as an
//! arrival. See [`SentRun::classify_echo`].
//!
//! # Layout (v2, 64 bytes, all integers big-endian)
//!
//! ```text
//!  off  0  u32   nonce         run kind: PROBE_NONCE | CALIBRATION_NONCE
//!  off  4  u32   marker        datagram index within the run
//!  off  8  u64   session       random per run; kills cross-run replay
//!  off 16  u64   session_tag   HMAC(K, "lok/sess/v2" || nonce || session)[..8]
//!  off 24  u64   leg_tag       request:  HMAC(K, "lok/req/v2"  || header || payload)[..8]
//!                              response: HMAC(K, "lok/resp/v2" || header || payload)[..8]
//!  off 32  [32]  payload       HMAC(K, "lok/pay/v2" || header)
//! ```
//!
//! `session_tag` deliberately covers **only** `nonce` and `session`, not the marker or the
//! payload. That is what lets the server authenticate a run (and refuse to echo anything
//! else — an unauthenticated open UDP echo on a rented VPS is a reflector, and an abuse
//! report is one null-route away from looking like a censorship finding) while still
//! echoing datagrams whose marker or payload were rewritten in flight, which is exactly
//! the evidence hole 1 needs.
//!
//! **The residual blind spot, stated plainly:** a forward-leg rewrite of the 20 bytes that
//! authenticate the run (`nonce`, `session`, `session_tag`) makes the server discard the
//! datagram, and it still reads as a drop. That is a deliberate trade against running an
//! open reflector. Every other byte — marker and payload — is echoed and its rewrite
//! detected.

pub mod sha256;

use sha256::{hmac_sha256, hmac_tag64};

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

pub const DATAGRAM_LEN: usize = 64;
pub const PAYLOAD_LEN: usize = 32;
pub const PAYLOAD_OFF: usize = 32;

const NONCE_OFF: usize = 0;
const MARKER_OFF: usize = 4;
const SESSION_OFF: usize = 8;
const SESSION_TAG_OFF: usize = 16;
const LEG_TAG_OFF: usize = 24;

/// Nonce marking a datagram as a probe-battery run's.
pub const PROBE_NONCE: u32 = 0xA1B2_C3D4;
/// Nonce for the TTL-calibration datagram, kept distinct so it is never counted as a
/// marker observation.
pub const CALIBRATION_NONCE: u32 = 0xC0FF_EE00;

const DOM_SESSION: &[u8] = b"lok/sess/v2";
const DOM_REQUEST: &[u8] = b"lok/req/v2";
const DOM_RESPONSE: &[u8] = b"lok/resp/v2";
const DOM_PAYLOAD: &[u8] = b"lok/pay/v2";

/// How many of the 32 payload bytes may differ and still attribute an echo to the marker
/// whose payload it is nearest to. A middlebox rewrites a field, not a packet: past this
/// the "nearest sent datagram" claim stops being evidence and the echo is unattributable.
pub const MAX_PAYLOAD_DRIFT: usize = 8;

// ---------------------------------------------------------------------------
// Key
// ---------------------------------------------------------------------------

/// The shared secret both ends of the delta hold. Provisioned out of band (see
/// `deploy/DEPLOY.md`) and read from `LOK_PROBE_KEY` as 64 hex characters.
#[derive(Clone, Copy)]
pub struct Key {
    bytes: [u8; 32],
    keyed: bool,
}

/// Environment variable carrying the shared secret, 64 hex chars.
pub const KEY_ENV: &str = "LOK_PROBE_KEY";

impl Key {
    /// The published, secret-free key used when no shared secret is configured. Mutation
    /// detection still works with it — that only needs both ends to agree. **Forgery
    /// detection does not**: anyone can compute these tags. A run made with this key
    /// reports `keyed: false` so a verdict is never read as stronger than it is.
    ///
    /// The domain tag says `lok/`, not the project name, and that is load-bearing rather
    /// than cosmetic: this literal is compiled into the probe, so the old spelling meant
    /// `strings /usr/local/bin/<prefix>-probe` on an RU sensor printed the project name.
    /// That is the one place the `LOK_PREFIX` namespacing cannot reach, and it defeats the
    /// invariant for the same reason — the name links the box to the public repo. Bumped
    /// v2 -> v3 because the derived key changes with the tag: an old and a new binary will
    /// not agree in open mode, and a version bump makes that a clean mismatch rather than a
    /// silent one. Keyed runs are unaffected; they never derive from this.
    pub fn open() -> Key {
        Key { bytes: sha256::sha256(&[b"lok/open-mode/v3"]), keyed: false }
    }

    /// Parse 64 hex characters into a key. `None` on any other shape — a truncated or
    /// mistyped secret must fail loudly, not silently weaken every verdict.
    pub fn from_hex(s: &str) -> Option<Key> {
        let s = s.trim();
        if s.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(Key { bytes, keyed: true })
    }

    /// Read [`KEY_ENV`], falling back to [`Key::open`]. `Err` carries a human-readable
    /// reason for the fallback, for the caller to warn about once.
    pub fn from_env() -> Result<Key, (Key, &'static str)> {
        match std::env::var(KEY_ENV) {
            Err(_) => Err((Key::open(), "not set")),
            Ok(v) => Key::from_hex(&v).ok_or((Key::open(), "not 64 hex characters")),
        }
    }

    /// Whether a real shared secret is in use (as opposed to the published open-mode key).
    pub fn is_keyed(self) -> bool {
        self.keyed
    }
}

impl std::fmt::Debug for Key {
    /// Never print key material: this type ends up in `Debug`-formatted error paths.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({})", if self.keyed { "configured" } else { "open-mode" })
    }
}

// ---------------------------------------------------------------------------
// Header + tags
// ---------------------------------------------------------------------------

/// The identifying fields of a datagram. Rewriting any of these in flight is what the
/// keyed payload exists to survive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub nonce: u32,
    pub marker: u32,
    pub session: u64,
}

impl Header {
    fn bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&self.nonce.to_be_bytes());
        out[4..8].copy_from_slice(&self.marker.to_be_bytes());
        out[8..16].copy_from_slice(&self.session.to_be_bytes());
        out
    }
}

/// The run authenticator: covers the nonce and session only, so a rewritten marker or
/// payload still reaches the server (and comes back as evidence).
pub fn session_tag(key: &Key, nonce: u32, session: u64) -> u64 {
    hmac_tag64(&key.bytes, &[DOM_SESSION, &nonce.to_be_bytes(), &session.to_be_bytes()])
}

/// The keyed payload for a header — 32 bytes that identify the datagram on their own.
pub fn payload_for(key: &Key, header: &Header) -> [u8; PAYLOAD_LEN] {
    hmac_sha256(&key.bytes, &[DOM_PAYLOAD, &header.bytes()])
}

/// Which direction a datagram was travelling when it was tagged. Domain separation is the
/// whole anti-spoof property: a reflector can only replay a *request* tag, which is not
/// what the probe accepts as an arrival.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Request,
    Response,
}

impl Dir {
    fn domain(self) -> &'static [u8] {
        match self {
            Dir::Request => DOM_REQUEST,
            Dir::Response => DOM_RESPONSE,
        }
    }
}

/// The leg tag over a header and payload, in one direction.
pub fn leg_tag(key: &Key, dir: Dir, header: &Header, payload: &[u8]) -> u64 {
    hmac_tag64(&key.bytes, &[dir.domain(), &header.bytes(), payload])
}

// ---------------------------------------------------------------------------
// Build / parse
// ---------------------------------------------------------------------------

/// A parsed datagram: exactly the fields as they arrived, with no judgement applied.
#[derive(Debug, Clone, Copy)]
pub struct Parsed {
    pub header: Header,
    pub session_tag: u64,
    pub leg_tag: u64,
    pub payload: [u8; PAYLOAD_LEN],
}

/// Parse a datagram. `None` unless it is exactly [`DATAGRAM_LEN`] bytes — a short or long
/// datagram is not one of ours, and guessing at a truncated one would invent evidence.
pub fn parse(buf: &[u8]) -> Option<Parsed> {
    if buf.len() != DATAGRAM_LEN {
        return None;
    }
    let be32 = |off: usize| u32::from_be_bytes(buf[off..off + 4].try_into().unwrap());
    let be64 = |off: usize| u64::from_be_bytes(buf[off..off + 8].try_into().unwrap());
    let mut payload = [0u8; PAYLOAD_LEN];
    payload.copy_from_slice(&buf[PAYLOAD_OFF..]);
    Some(Parsed {
        header: Header { nonce: be32(NONCE_OFF), marker: be32(MARKER_OFF), session: be64(SESSION_OFF) },
        session_tag: be64(SESSION_TAG_OFF),
        leg_tag: be64(LEG_TAG_OFF),
        payload,
    })
}

/// Build the request datagram for `header`.
pub fn build_request(key: &Key, header: &Header) -> [u8; DATAGRAM_LEN] {
    let payload = payload_for(key, header);
    let mut buf = [0u8; DATAGRAM_LEN];
    buf[NONCE_OFF..NONCE_OFF + 4].copy_from_slice(&header.nonce.to_be_bytes());
    buf[MARKER_OFF..MARKER_OFF + 4].copy_from_slice(&header.marker.to_be_bytes());
    buf[SESSION_OFF..SESSION_OFF + 8].copy_from_slice(&header.session.to_be_bytes());
    buf[SESSION_TAG_OFF..SESSION_TAG_OFF + 8]
        .copy_from_slice(&session_tag(key, header.nonce, header.session).to_be_bytes());
    buf[PAYLOAD_OFF..].copy_from_slice(&payload);
    let tag = leg_tag(key, Dir::Request, header, &payload);
    buf[LEG_TAG_OFF..LEG_TAG_OFF + 8].copy_from_slice(&tag.to_be_bytes());
    buf
}

/// Whether a received datagram authenticates as belonging to one of our runs. This is the
/// server's admission check: fail it and the datagram is discarded unanswered, so the
/// server is not an open reflector.
pub fn is_authentic_request(key: &Key, p: &Parsed) -> bool {
    p.session_tag == session_tag(key, p.header.nonce, p.header.session)
}

/// Build the response to a received datagram: the received bytes verbatim, with the leg
/// tag replaced by a response tag over **what the server actually received**.
///
/// Signing what arrived (rather than what "should" have arrived) is what lets the probe
/// tell a forward-leg rewrite from a return-leg one: see [`SentRun::classify_echo`].
pub fn build_response(key: &Key, received: &[u8; DATAGRAM_LEN]) -> [u8; DATAGRAM_LEN] {
    let mut buf = *received;
    let p = parse(received).expect("fixed-length datagram parses");
    let tag = leg_tag(key, Dir::Response, &p.header, &p.payload);
    buf[LEG_TAG_OFF..LEG_TAG_OFF + 8].copy_from_slice(&tag.to_be_bytes());
    buf
}

// ---------------------------------------------------------------------------
// Echo attribution
// ---------------------------------------------------------------------------

/// Which leg of the round trip a rewrite happened on. Recoverable because the server signs
/// what it received: if the response tag verifies over the bytes we *sent*, the rewrite is
/// downstream of the server; if it verifies over the bytes we *received*, it is upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    /// Sensor → server: the server saw the rewritten bytes.
    Forward,
    /// Server → sensor: the server saw the original bytes.
    Return,
}

/// What one received echo actually is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Echo {
    /// A server-signed echo of `marker`, byte for byte as sent.
    Intact { marker: u32 },
    /// A server-signed echo of `marker` with bytes rewritten in flight. `header` and
    /// `payload` name which part was rewritten and on which leg.
    Mutated { marker: u32, header: Option<Leg>, payload: Option<Leg> },
    /// A verbatim copy of one of our own requests: something on the path reflected the
    /// probe instead of delivering it. **Never** an arrival — that is the point of the key.
    Reflected { marker: u32 },
    /// Carries no valid server tag, and no sent datagram it could be. Counted, never
    /// scored as an arrival: an unauthenticated echo is not evidence of delivery.
    Unauthenticated,
}

/// One probe run's sent side — enough to recognise anything that comes back.
#[derive(Debug, Clone, Copy)]
pub struct SentRun {
    pub key: Key,
    pub nonce: u32,
    pub session: u64,
    pub count: u32,
}

impl SentRun {
    pub fn header(&self, marker: u32) -> Header {
        Header { nonce: self.nonce, marker, session: self.session }
    }

    pub fn request(&self, marker: u32) -> [u8; DATAGRAM_LEN] {
        build_request(&self.key, &self.header(marker))
    }

    /// Attribute a received payload to the marker whose keyed payload it is (or is nearest
    /// to). Exact match wins outright; otherwise the nearest within [`MAX_PAYLOAD_DRIFT`]
    /// bytes, and only if that nearest is unique — a tie is not evidence.
    fn attribute(&self, payload: &[u8; PAYLOAD_LEN]) -> Option<u32> {
        let mut best: Option<(usize, u32)> = None;
        let mut tied = false;
        for marker in 0..self.count {
            let expected = payload_for(&self.key, &self.header(marker));
            let dist = expected.iter().zip(payload).filter(|(a, b)| a != b).count();
            if dist == 0 {
                return Some(marker);
            }
            match best {
                Some((d, _)) if dist > d => {}
                Some((d, _)) if dist == d => tied = true,
                _ => {
                    best = Some((dist, marker));
                    tied = false;
                }
            }
        }
        match best {
            Some((dist, marker)) if dist <= MAX_PAYLOAD_DRIFT && !tied => Some(marker),
            _ => None,
        }
    }

    /// Decide what a received datagram is. The order matters: attribute by the keyed
    /// payload first (that survives a destroyed header), then read the leg tag to decide
    /// whether the far end signed it — and, if bytes were rewritten, on which leg.
    pub fn classify_echo(&self, buf: &[u8]) -> Echo {
        let Some(recv) = parse(buf) else {
            return Echo::Unauthenticated;
        };
        let Some(marker) = self.attribute(&recv.payload) else {
            return Echo::Unauthenticated;
        };

        let sent_header = self.header(marker);
        let sent_payload = payload_for(&self.key, &sent_header);

        // Our own request, bounced back by something that cannot sign a response.
        if recv.leg_tag == leg_tag(&self.key, Dir::Request, &recv.header, &recv.payload) {
            return Echo::Reflected { marker };
        }

        // The server signs what it received. Whichever of the four (header, payload)
        // combinations verifies tells us which side of the server each rewrite happened on.
        let header_mutated = recv.header != sent_header;
        let payload_mutated = recv.payload != sent_payload;
        for (h_leg, header) in [(Leg::Forward, &recv.header), (Leg::Return, &sent_header)] {
            for (p_leg, payload) in
                [(Leg::Forward, &recv.payload), (Leg::Return, &sent_payload)]
            {
                if recv.leg_tag == leg_tag(&self.key, Dir::Response, header, payload) {
                    if !header_mutated && !payload_mutated {
                        return Echo::Intact { marker };
                    }
                    return Echo::Mutated {
                        marker,
                        header: header_mutated.then_some(h_leg),
                        payload: payload_mutated.then_some(p_leg),
                    };
                }
            }
        }

        Echo::Unauthenticated
    }
}

/// A fresh 64-bit session id. `/dev/urandom` where it exists; otherwise a clock/pid mix,
/// which is enough for its job (making one run's tags distinct from another's, so a
/// captured echo cannot be replayed into a later run).
pub fn new_session() -> u64 {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let mut b = [0u8; 8];
        if f.read_exact(&mut b).is_ok() {
            return u64::from_be_bytes(b);
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mix = sha256::sha256(&[&nanos.to_be_bytes(), &std::process::id().to_be_bytes()]);
    u64::from_be_bytes(mix[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> SentRun {
        SentRun { key: Key::open(), nonce: PROBE_NONCE, session: 0x0123_4567_89AB_CDEF, count: 8 }
    }

    fn echoed(r: &SentRun, marker: u32) -> [u8; DATAGRAM_LEN] {
        build_response(&r.key, &r.request(marker))
    }

    #[test]
    fn key_parsing_rejects_anything_but_64_hex() {
        assert!(Key::from_hex(&"ab".repeat(32)).is_some());
        assert!(Key::from_hex(&"ab".repeat(31)).is_none(), "short key must not silently pass");
        assert!(Key::from_hex(&"zz".repeat(32)).is_none());
        assert!(!Key::open().is_keyed());
        assert!(Key::from_hex(&"ab".repeat(32)).unwrap().is_keyed());
    }

    #[test]
    fn payload_is_marker_and_session_specific() {
        let r = run();
        assert_ne!(payload_for(&r.key, &r.header(0)), payload_for(&r.key, &r.header(1)));
        let other = SentRun { session: r.session ^ 1, ..r };
        assert_ne!(
            payload_for(&r.key, &r.header(3)),
            payload_for(&other.key, &other.header(3)),
            "a later run must not accept an earlier run's echo"
        );
    }

    #[test]
    fn a_real_echo_is_intact() {
        let r = run();
        for marker in 0..r.count {
            assert_eq!(r.classify_echo(&echoed(&r, marker)), Echo::Intact { marker });
        }
    }

    /// Hole 2: a middlebox that drops the datagram and bounces the request back cannot be
    /// scored as delivery. This is the property the key exists for.
    #[test]
    fn a_reflected_request_is_never_an_arrival() {
        let r = run();
        assert_eq!(r.classify_echo(&r.request(5)), Echo::Reflected { marker: 5 });
    }

    /// Hole 1: the marker rewritten on the way back. The keyed payload still names the
    /// datagram, so this is a mutation — not the fabricated drop the MVP reported.
    #[test]
    fn marker_rewritten_on_the_return_leg_is_attributed_and_located() {
        let r = run();
        let mut buf = echoed(&r, 3);
        buf[MARKER_OFF] = 0xFF; // rewrite after the server signed it
        assert_eq!(
            r.classify_echo(&buf),
            Echo::Mutated { marker: 3, header: Some(Leg::Return), payload: None }
        );
    }

    /// The same rewrite on the way out: the server signs the mutated header, so the leg
    /// reads Forward. Distinguishing the two is free once the server signs what it saw.
    #[test]
    fn marker_rewritten_on_the_forward_leg_reads_as_forward() {
        let r = run();
        let mut req = r.request(3);
        req[MARKER_OFF] = 0xFF;
        let buf = build_response(&r.key, &req);
        assert_eq!(
            r.classify_echo(&buf),
            Echo::Mutated { marker: 3, header: Some(Leg::Forward), payload: None }
        );
    }

    #[test]
    fn payload_rewrite_is_attributed_and_located_per_leg() {
        let r = run();
        let mut back = echoed(&r, 2);
        back[PAYLOAD_OFF] ^= 0xFF;
        assert_eq!(
            r.classify_echo(&back),
            Echo::Mutated { marker: 2, header: None, payload: Some(Leg::Return) }
        );

        let mut req = r.request(2);
        req[PAYLOAD_OFF] ^= 0xFF;
        let out = build_response(&r.key, &req);
        assert_eq!(
            r.classify_echo(&out),
            Echo::Mutated { marker: 2, header: None, payload: Some(Leg::Forward) }
        );
    }

    #[test]
    fn a_payload_rewritten_past_the_drift_bound_is_unattributable() {
        let r = run();
        let mut buf = echoed(&r, 1);
        for b in buf[PAYLOAD_OFF..PAYLOAD_OFF + MAX_PAYLOAD_DRIFT + 1].iter_mut() {
            *b ^= 0xFF;
        }
        assert_eq!(r.classify_echo(&buf), Echo::Unauthenticated);
    }

    /// A forged tag over a payload the forger could only have obtained by seeing (and
    /// dropping) the real datagram. Attributable, but not signed — so not an arrival.
    #[test]
    fn a_forged_tag_is_not_an_arrival() {
        let r = run();
        let mut buf = echoed(&r, 4);
        buf[LEG_TAG_OFF] ^= 0xFF;
        assert_eq!(r.classify_echo(&buf), Echo::Unauthenticated);
    }

    #[test]
    fn a_run_rejects_another_keys_echo() {
        let r = run();
        let impostor = SentRun { key: Key::from_hex(&"11".repeat(32)).unwrap(), ..r };
        let buf = build_response(&impostor.key, &impostor.request(2));
        assert_eq!(r.classify_echo(&buf), Echo::Unauthenticated);
    }

    #[test]
    fn short_and_long_datagrams_are_not_ours() {
        let r = run();
        let buf = echoed(&r, 0);
        assert_eq!(r.classify_echo(&buf[..DATAGRAM_LEN - 1]), Echo::Unauthenticated);
        let mut long = buf.to_vec();
        long.push(0);
        assert_eq!(r.classify_echo(&long), Echo::Unauthenticated);
    }

    #[test]
    fn the_server_admits_only_authenticated_runs() {
        let r = run();
        let req = r.request(0);
        assert!(is_authentic_request(&r.key, &parse(&req).unwrap()));

        // Random traffic aimed at the port: no valid session tag, so no reply is sent.
        let junk = [0x42u8; DATAGRAM_LEN];
        assert!(!is_authentic_request(&r.key, &parse(&junk).unwrap()));

        // A rewritten marker still authenticates — that is deliberate: the server must
        // echo it so the rewrite becomes visible rather than reading as a drop.
        let mut mangled = req;
        mangled[MARKER_OFF] = 0xFF;
        assert!(is_authentic_request(&r.key, &parse(&mangled).unwrap()));

        // A rewritten session does not, and is the documented blind spot.
        let mut resigned = req;
        resigned[SESSION_OFF] ^= 0xFF;
        assert!(!is_authentic_request(&r.key, &parse(&resigned).unwrap()));
    }
}
