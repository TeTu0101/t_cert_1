#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, contracterror,
    Address, Bytes, BytesN, Env, String, Vec,
    log, panic_with_error,
};

// ─────────────────────────────────────────────
// Error codes
// ─────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ContractError {
    // Auth / access
    Unauthorized             = 1,
    Blacklisted              = 2,

    // Event lifecycle
    EventNotFound            = 10,
    EventAlreadyExists       = 11,
    EventNotActive           = 12,
    EventAlreadyEnded        = 13,

    // Registration
    NotRegistered            = 20,
    AlreadyRegistered        = 21,

    // Check-in
    AlreadyCheckedIn         = 30,
    NotCheckedIn             = 31,
    FaceVerificationFailed   = 32,

    // QR / nonce
    InvalidNonce             = 40,
    NonceExpired             = 41,
    NonceAlreadyUsed         = 42,

    // Presence ping
    NoPingActive             = 50,
    PingWindowExpired        = 51,
    AlreadyConfirmedPing     = 52,

    // Check-out / certificate
    AlreadyCheckedOut        = 60,
    AttendanceInsufficient   = 61,
    CertificateAlreadyMinted = 62,
    NotEligible              = 63,
}

// ─────────────────────────────────────────────
// Storage keys
// ─────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Event(u64),
    EventCounter,
    Registration(u64, Address),
    Attendee(u64, Address),
    Nonce(BytesN<32>),
    ActivePing(u64),
    Blacklist(Address),
    Certificate(u64, Address),
    FraudRecord(Address),
}

// ─────────────────────────────────────────────
// Core data types
// ─────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct EventData {
    pub event_id:    u64,
    pub name:        String,
    pub organizer:   Address,
    pub start_time:  u64,
    pub end_time:    u64,
    pub location:    String,
    pub total_pings: u32,
    pub active:      bool,
    pub ended:       bool,
}

#[contracttype]
#[derive(Clone)]
pub struct RegistrationData {
    pub attendee:      Address,
    pub event_id:      u64,
    pub registered_at: u64,
    /// SHA-256 hash of the face image stored off-chain (e.g. IPFS CID).
    pub face_hash:     BytesN<32>,
}

#[contracttype]
#[derive(Clone)]
pub struct AttendeeData {
    pub attendee:           Address,
    pub event_id:           u64,
    pub checked_in:         bool,
    pub checkin_time:       u64,
    pub checked_out:        bool,
    pub checkout_time:      u64,
    /// IPFS hash of the selfie captured at check-in time.
    pub checkin_face_proof: BytesN<32>,
    /// Indices of the pings this attendee successfully confirmed.
    pub confirmed_pings:    Vec<u32>,
    pub marked_absent:      bool,
    pub eligible:           bool,
}

/// One-time-use QR nonce record.
/// nonce_type: 0 = check-in, 1 = presence-ping, 2 = check-out.
#[contracttype]
#[derive(Clone)]
pub struct NonceRecord {
    pub nonce_hash:  BytesN<32>,
    pub event_id:    u64,
    pub created_at:  u64,
    pub expires_at:  u64,
    pub used:        bool,
    pub nonce_type:  u32,
    pub ping_index:  u32,
}

#[contracttype]
#[derive(Clone)]
pub struct PingData {
    pub event_id:   u64,
    pub ping_index: u32,
    pub opened_at:  u64,
    pub expires_at: u64,
    pub closed:     bool,
}

#[contracttype]
#[derive(Clone)]
pub struct CertificateData {
    pub cert_id:          BytesN<32>,
    pub event_id:         u64,
    pub attendee:         Address,
    pub issued_at:        u64,
    /// Basis points: 10000 = 100 %, 9000 = 90 %
    pub attendance_ratio: u32,
    pub event_name:       String,
    pub revoked:          bool,
}

#[contracttype]
#[derive(Clone)]
pub struct FraudEntry {
    pub event_id:    u64,
    pub detected_at: u64,
    pub reason:      String,
}

#[contracttype]
#[derive(Clone)]
pub struct BlacklistRecord {
    pub address:        Address,
    pub blacklisted_at: u64,
    pub reason:         String,
}

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────

const NONCE_TTL_SECS:     u64 = 15;
const PING_WINDOW_SECS:   u64 = 240;
const MIN_ATTENDANCE_BPS: u32 = 9_000;

const NONCE_CHECKIN:  u32 = 0;
const NONCE_PING:     u32 = 1;
const NONCE_CHECKOUT: u32 = 2;

// ─────────────────────────────────────────────
// Contract
// ─────────────────────────────────────────────

#[contract]
pub struct CertificationContract;

#[contractimpl]
impl CertificationContract {

    // ─── Initialisation ───────────────────────────────────────────────

    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(&env, ContractError::Unauthorized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::EventCounter, &0u64);
    }

    // ─── Admin helpers ────────────────────────────────────────────────

    fn require_admin(env: &Env) -> Address {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        admin
    }

    fn require_not_blacklisted(env: &Env, addr: &Address) {
        if env.storage().persistent().has(&DataKey::Blacklist(addr.clone())) {
            panic_with_error!(env, ContractError::Blacklisted);
        }
    }

    // ─── Event management ─────────────────────────────────────────────

    pub fn create_event(
        env:         Env,
        name:        String,
        organizer:   Address,
        start_time:  u64,
        end_time:    u64,
        location:    String,
        total_pings: u32,
    ) -> u64 {
        Self::require_admin(&env);

        let mut counter: u64 = env.storage().instance()
            .get(&DataKey::EventCounter).unwrap_or(0);
        counter += 1;

        let event = EventData {
            event_id: counter,
            name,
            organizer,
            start_time,
            end_time,
            location,
            total_pings,
            active: true,
            ended:  false,
        };

        env.storage().persistent().set(&DataKey::Event(counter), &event);
        env.storage().instance().set(&DataKey::EventCounter, &counter);

        log!(&env, "event created: {}", counter);
        counter
    }

    pub fn end_event(env: Env, event_id: u64) {
        Self::require_admin(&env);
        let mut event = Self::get_event_or_panic(&env, event_id);
        event.active = false;
        event.ended  = true;
        env.storage().persistent().set(&DataKey::Event(event_id), &event);
    }

    // ─── Registration ─────────────────────────────────────────────────

    pub fn register(
        env:       Env,
        event_id:  u64,
        attendee:  Address,
        face_hash: BytesN<32>,
    ) {
        attendee.require_auth();
        Self::require_not_blacklisted(&env, &attendee);

        let event = Self::get_event_or_panic(&env, event_id);
        if !event.active {
            panic_with_error!(&env, ContractError::EventNotActive);
        }

        let reg_key = DataKey::Registration(event_id, attendee.clone());
        if env.storage().persistent().has(&reg_key) {
            panic_with_error!(&env, ContractError::AlreadyRegistered);
        }

        let reg = RegistrationData {
            attendee:      attendee.clone(),
            event_id,
            registered_at: env.ledger().timestamp(),
            face_hash,
        };
        env.storage().persistent().set(&reg_key, &reg);
    }

    // ─── QR Nonce management ──────────────────────────────────────────

    pub fn register_nonce(
        env:        Env,
        nonce_hash: BytesN<32>,
        event_id:   u64,
        nonce_type: u32,
        ping_index: u32,
    ) {
        Self::require_admin(&env);

        let key = DataKey::Nonce(nonce_hash.clone());
        if env.storage().temporary().has(&key) {
            panic_with_error!(&env, ContractError::NonceAlreadyUsed);
        }

        let now = env.ledger().timestamp();
        let record = NonceRecord {
            nonce_hash,
            event_id,
            created_at: now,
            expires_at: now + NONCE_TTL_SECS,
            used:       false,
            nonce_type,
            ping_index,
        };
        env.storage().temporary().set(&key, &record);
    }

    fn consume_nonce(env: &Env, nonce_hash: BytesN<32>) -> NonceRecord {
        let key = DataKey::Nonce(nonce_hash.clone());

        let mut record: NonceRecord = env.storage().temporary()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(env, ContractError::InvalidNonce));

        if record.used {
            panic_with_error!(env, ContractError::NonceAlreadyUsed);
        }
        if env.ledger().timestamp() > record.expires_at {
            panic_with_error!(env, ContractError::NonceExpired);
        }

        record.used = true;
        env.storage().temporary().set(&key, &record);
        record
    }

    // ─── Check-in (Layer 1 + Layer 2) ─────────────────────────────────

    pub fn check_in(
        env:             Env,
        event_id:        u64,
        attendee:        Address,
        nonce_hash:      BytesN<32>,
        face_proof_hash: BytesN<32>,
        face_match:      bool,
    ) {
        attendee.require_auth();
        Self::require_not_blacklisted(&env, &attendee);

        let reg_key = DataKey::Registration(event_id, attendee.clone());
        if !env.storage().persistent().has(&reg_key) {
            panic_with_error!(&env, ContractError::NotRegistered);
        }

        let event = Self::get_event_or_panic(&env, event_id);
        if !event.active {
            panic_with_error!(&env, ContractError::EventNotActive);
        }

        let att_key = DataKey::Attendee(event_id, attendee.clone());
        if env.storage().persistent().has(&att_key) {
            let existing: AttendeeData = env.storage().persistent().get(&att_key).unwrap();
            if existing.checked_in {
                panic_with_error!(&env, ContractError::AlreadyCheckedIn);
            }
        }

        let nonce = Self::consume_nonce(&env, nonce_hash);
        if nonce.event_id != event_id || nonce.nonce_type != NONCE_CHECKIN {
            panic_with_error!(&env, ContractError::InvalidNonce);
        }

        if !face_match {
            panic_with_error!(&env, ContractError::FaceVerificationFailed);
        }

        let now = env.ledger().timestamp();
        let attendee_data = AttendeeData {
            attendee:           attendee.clone(),
            event_id,
            checked_in:         true,
            checkin_time:       now,
            checked_out:        false,
            checkout_time:      0,
            checkin_face_proof: face_proof_hash,
            confirmed_pings:    Vec::new(&env),
            marked_absent:      false,
            eligible:           false,
        };
        env.storage().persistent().set(&att_key, &attendee_data);
        log!(&env, "checked in: event={}", event_id);
    }

    // ─── Presence pings (Layer 3) ──────────────────────────────────────

    pub fn open_ping(env: Env, event_id: u64, ping_index: u32) {
        Self::require_admin(&env);

        let event = Self::get_event_or_panic(&env, event_id);
        if !event.active {
            panic_with_error!(&env, ContractError::EventNotActive);
        }

        let now = env.ledger().timestamp();
        let ping = PingData {
            event_id,
            ping_index,
            opened_at:  now,
            expires_at: now + PING_WINDOW_SECS,
            closed:     false,
        };
        env.storage().persistent().set(&DataKey::ActivePing(event_id), &ping);
        log!(&env, "ping opened: event={} index={}", event_id, ping_index);
    }

    pub fn close_ping(env: Env, event_id: u64) {
        Self::require_admin(&env);
        let ping_key = DataKey::ActivePing(event_id);
        let mut ping: PingData = env.storage().persistent()
            .get(&ping_key)
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::NoPingActive));
        ping.closed = true;
        env.storage().persistent().set(&ping_key, &ping);
    }

    pub fn confirm_ping(
        env:        Env,
        event_id:   u64,
        attendee:   Address,
        nonce_hash: BytesN<32>,
    ) {
        attendee.require_auth();
        Self::require_not_blacklisted(&env, &attendee);

        let att_key = DataKey::Attendee(event_id, attendee.clone());
        let mut att: AttendeeData = env.storage().persistent()
            .get(&att_key)
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::NotCheckedIn));
        if !att.checked_in {
            panic_with_error!(&env, ContractError::NotCheckedIn);
        }

        let ping_key = DataKey::ActivePing(event_id);
        let ping: PingData = env.storage().persistent()
            .get(&ping_key)
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::NoPingActive));

        if ping.closed {
            panic_with_error!(&env, ContractError::NoPingActive);
        }
        if env.ledger().timestamp() > ping.expires_at {
            panic_with_error!(&env, ContractError::PingWindowExpired);
        }

        for i in 0..att.confirmed_pings.len() {
            if att.confirmed_pings.get(i).unwrap() == ping.ping_index {
                panic_with_error!(&env, ContractError::AlreadyConfirmedPing);
            }
        }

        let nonce = Self::consume_nonce(&env, nonce_hash);
        if nonce.event_id != event_id
            || nonce.nonce_type != NONCE_PING
            || nonce.ping_index != ping.ping_index
        {
            panic_with_error!(&env, ContractError::InvalidNonce);
        }

        att.confirmed_pings.push_back(ping.ping_index);
        env.storage().persistent().set(&att_key, &att);
        log!(&env, "ping confirmed: event={} ping={}", event_id, ping.ping_index);
    }

    pub fn mark_absent_for_missed_ping(
        env:        Env,
        event_id:   u64,
        attendees:  Vec<Address>,
        ping_index: u32,
    ) {
        Self::require_admin(&env);

        for i in 0..attendees.len() {
            let addr = attendees.get(i).unwrap();
            let att_key = DataKey::Attendee(event_id, addr.clone());
            if let Some(mut att) = env.storage().persistent()
                .get::<DataKey, AttendeeData>(&att_key)
            {
                let mut confirmed = false;
                for j in 0..att.confirmed_pings.len() {
                    if att.confirmed_pings.get(j).unwrap() == ping_index {
                        confirmed = true;
                        break;
                    }
                }
                if !confirmed {
                    att.marked_absent = true;
                    env.storage().persistent().set(&att_key, &att);
                }
            }
        }
    }

    // ─── Check-out ────────────────────────────────────────────────────

    pub fn check_out(
        env:        Env,
        event_id:   u64,
        attendee:   Address,
        nonce_hash: BytesN<32>,
    ) {
        attendee.require_auth();
        Self::require_not_blacklisted(&env, &attendee);

        let att_key = DataKey::Attendee(event_id, attendee.clone());
        let mut att: AttendeeData = env.storage().persistent()
            .get(&att_key)
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::NotCheckedIn));

        if !att.checked_in {
            panic_with_error!(&env, ContractError::NotCheckedIn);
        }
        if att.checked_out {
            panic_with_error!(&env, ContractError::AlreadyCheckedOut);
        }

        let nonce = Self::consume_nonce(&env, nonce_hash);
        if nonce.event_id != event_id || nonce.nonce_type != NONCE_CHECKOUT {
            panic_with_error!(&env, ContractError::InvalidNonce);
        }

        let event = Self::get_event_or_panic(&env, event_id);

        att.checked_out   = true;
        att.checkout_time = env.ledger().timestamp();

        let total     = event.total_pings;
        let confirmed = att.confirmed_pings.len();
        let ratio_bps: u32 = if total == 0 {
            10_000
        } else {
            (confirmed as u32 * 10_000) / total
        };

        att.eligible = ratio_bps >= MIN_ATTENDANCE_BPS;
        env.storage().persistent().set(&att_key, &att);
        log!(&env, "checked out: event={} ratio_bps={} eligible={}", event_id, ratio_bps, att.eligible);
    }

    // ─── Certificate minting ──────────────────────────────────────────

    pub fn mint_certificate(env: Env, event_id: u64, attendee: Address) -> BytesN<32> {
        attendee.require_auth();
        Self::require_not_blacklisted(&env, &attendee);

        let att_key = DataKey::Attendee(event_id, attendee.clone());
        let att: AttendeeData = env.storage().persistent()
            .get(&att_key)
            .unwrap_or_else(|| panic_with_error!(&env, ContractError::NotCheckedIn));

        if !att.eligible {
            panic_with_error!(&env, ContractError::NotEligible);
        }

        let cert_key = DataKey::Certificate(event_id, attendee.clone());
        if env.storage().persistent().has(&cert_key) {
            panic_with_error!(&env, ContractError::CertificateAlreadyMinted);
        }

        let event     = Self::get_event_or_panic(&env, event_id);
        let now       = env.ledger().timestamp();
        let total     = event.total_pings;
        let confirmed = att.confirmed_pings.len();
        let ratio_bps = if total == 0 { 10_000u32 } else { (confirmed as u32 * 10_000) / total };

        // SDK v25: sha256() returns Hash<32>, convert to BytesN<32> with .into()
        let mut id_seed = Bytes::new(&env);
        id_seed.extend_from_array(&event_id.to_be_bytes());
        id_seed.extend_from_array(&now.to_be_bytes());
        let cert_id: BytesN<32> = env.crypto().sha256(&id_seed).into();

        let cert = CertificateData {
            cert_id:          cert_id.clone(),
            event_id,
            attendee:         attendee.clone(),
            issued_at:        now,
            attendance_ratio: ratio_bps,
            event_name:       event.name,
            revoked:          false,
        };
        env.storage().persistent().set(&cert_key, &cert);
        log!(&env, "certificate minted: event={}", event_id);
        cert_id
    }

    // ─── Fraud handling ───────────────────────────────────────────────

    pub fn report_fraud(
        env:          Env,
        impersonator: Address,
        requester:    Address,
        event_id:     u64,
        reason:       String,
    ) {
        Self::require_admin(&env);
        let now = env.ledger().timestamp();

        for addr in [impersonator.clone(), requester.clone()] {
            let record = BlacklistRecord {
                address:        addr.clone(),
                blacklisted_at: now,
                reason:         reason.clone(),
            };
            env.storage().persistent().set(&DataKey::Blacklist(addr.clone()), &record);

            let fraud_key = DataKey::FraudRecord(addr.clone());
            let mut log_vec: Vec<FraudEntry> = env.storage().persistent()
                .get(&fraud_key)
                .unwrap_or_else(|| Vec::new(&env));
            log_vec.push_back(FraudEntry {
                event_id,
                detected_at: now,
                reason: reason.clone(),
            });
            env.storage().persistent().set(&fraud_key, &log_vec);

            let cert_key = DataKey::Certificate(event_id, addr.clone());
            if let Some(mut cert) = env.storage().persistent()
                .get::<DataKey, CertificateData>(&cert_key)
            {
                cert.revoked = true;
                env.storage().persistent().set(&cert_key, &cert);
            }
        }

        log!(&env, "fraud reported: event={}", event_id);
    }

    pub fn remove_from_blacklist(env: Env, addr: Address) {
        Self::require_admin(&env);
        env.storage().persistent().remove(&DataKey::Blacklist(addr));
    }

    // ─── Read-only queries ────────────────────────────────────────────

    pub fn get_event(env: Env, event_id: u64) -> Option<EventData> {
        env.storage().persistent().get(&DataKey::Event(event_id))
    }

    pub fn get_registration(env: Env, event_id: u64, attendee: Address) -> Option<RegistrationData> {
        env.storage().persistent().get(&DataKey::Registration(event_id, attendee))
    }

    pub fn get_attendee(env: Env, event_id: u64, attendee: Address) -> Option<AttendeeData> {
        env.storage().persistent().get(&DataKey::Attendee(event_id, attendee))
    }

    pub fn get_certificate(env: Env, event_id: u64, attendee: Address) -> Option<CertificateData> {
        env.storage().persistent().get(&DataKey::Certificate(event_id, attendee))
    }

    pub fn is_blacklisted(env: Env, addr: Address) -> bool {
        env.storage().persistent().has(&DataKey::Blacklist(addr))
    }

    pub fn get_fraud_records(env: Env, addr: Address) -> Vec<FraudEntry> {
        env.storage().persistent()
            .get(&DataKey::FraudRecord(addr))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_active_ping(env: Env, event_id: u64) -> Option<PingData> {
        env.storage().persistent().get(&DataKey::ActivePing(event_id))
    }

    // ─── Internal helpers ─────────────────────────────────────────────

    fn get_event_or_panic(env: &Env, event_id: u64) -> EventData {
        env.storage().persistent()
            .get(&DataKey::Event(event_id))
            .unwrap_or_else(|| panic_with_error!(env, ContractError::EventNotFound))
    }
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    fn setup() -> (Env, Address, CertificationContractClient<'static>) {
        let env    = Env::default();
        env.mock_all_auths();
        let admin  = Address::generate(&env);
        let cid    = env.register(CertificationContract, ());
        let client = CertificationContractClient::new(&env, &cid);
        client.initialize(&admin);
        (env, admin, client)
    }

    fn dummy_hash(env: &Env, seed: u8) -> BytesN<32> {
        let mut b = [0u8; 32];
        b[0] = seed;
        BytesN::from_array(env, &b)
    }

    #[test]
    fn test_full_happy_path() {
        let (env, _admin, client) = setup();
        let organizer = Address::generate(&env);
        let attendee  = Address::generate(&env);

        let event_id = client.create_event(
            &String::from_str(&env, "Hackathon 2025"),
            &organizer,
            &1_000_000u64,
            &1_003_600u64,
            &String::from_str(&env, "Room A"),
            &2u32,
        );

        client.register(&event_id, &attendee, &dummy_hash(&env, 1));

        let ci_nonce = dummy_hash(&env, 10);
        client.register_nonce(&ci_nonce, &event_id, &NONCE_CHECKIN, &0u32);
        client.check_in(&event_id, &attendee, &ci_nonce, &dummy_hash(&env, 2), &true);

        client.open_ping(&event_id, &0u32);
        let ping0_nonce = dummy_hash(&env, 20);
        client.register_nonce(&ping0_nonce, &event_id, &NONCE_PING, &0u32);
        client.confirm_ping(&event_id, &attendee, &ping0_nonce);

        client.open_ping(&event_id, &1u32);
        let ping1_nonce = dummy_hash(&env, 21);
        client.register_nonce(&ping1_nonce, &event_id, &NONCE_PING, &1u32);
        client.confirm_ping(&event_id, &attendee, &ping1_nonce);

        let co_nonce = dummy_hash(&env, 30);
        client.register_nonce(&co_nonce, &event_id, &NONCE_CHECKOUT, &0u32);
        client.check_out(&event_id, &attendee, &co_nonce);

        let att = client.get_attendee(&event_id, &attendee).unwrap();
        assert!(att.eligible);
        assert_eq!(att.confirmed_pings.len(), 2);

        let cert_id = client.mint_certificate(&event_id, &attendee);
        let cert    = client.get_certificate(&event_id, &attendee).unwrap();
        assert_eq!(cert.cert_id, cert_id);
        assert_eq!(cert.attendance_ratio, 10_000u32);
        assert!(!cert.revoked);
    }

    #[test]
    fn test_insufficient_attendance() {
        let (env, _admin, client) = setup();
        let organizer = Address::generate(&env);
        let attendee  = Address::generate(&env);

        let event_id = client.create_event(
            &String::from_str(&env, "Workshop"),
            &organizer,
            &1_000_000u64,
            &1_003_600u64,
            &String::from_str(&env, "Lab B"),
            &2u32,
        );
        client.register(&event_id, &attendee, &dummy_hash(&env, 1));

        let ci_nonce = dummy_hash(&env, 10);
        client.register_nonce(&ci_nonce, &event_id, &NONCE_CHECKIN, &0u32);
        client.check_in(&event_id, &attendee, &ci_nonce, &dummy_hash(&env, 2), &true);

        // Only 1 of 2 pings confirmed → 50 % < 90 %
        client.open_ping(&event_id, &0u32);
        let p_nonce = dummy_hash(&env, 20);
        client.register_nonce(&p_nonce, &event_id, &NONCE_PING, &0u32);
        client.confirm_ping(&event_id, &attendee, &p_nonce);

        let co_nonce = dummy_hash(&env, 30);
        client.register_nonce(&co_nonce, &event_id, &NONCE_CHECKOUT, &0u32);
        client.check_out(&event_id, &attendee, &co_nonce);

        let att = client.get_attendee(&event_id, &attendee).unwrap();
        assert!(!att.eligible);
    }

    #[test]
    fn test_fraud_blacklist_and_revoke() {
        let (env, _admin, client) = setup();
        let organizer    = Address::generate(&env);
        let impersonator = Address::generate(&env);
        let requester    = Address::generate(&env);

        let event_id = client.create_event(
            &String::from_str(&env, "Talk"),
            &organizer,
            &1_000_000u64,
            &1_003_600u64,
            &String::from_str(&env, "Hall"),
            &0u32,
        );
        client.register(&event_id, &requester, &dummy_hash(&env, 1));

        client.report_fraud(
            &impersonator,
            &requester,
            &event_id,
            &String::from_str(&env, "check-in on behalf"),
        );

        assert!(client.is_blacklisted(&impersonator));
        assert!(client.is_blacklisted(&requester));
        assert_eq!(client.get_fraud_records(&requester).len(), 1);
    }

    #[test]
    #[should_panic]
    fn test_nonce_reuse_rejected() {
        let (env, _admin, client) = setup();
        let organizer = Address::generate(&env);
        let a1 = Address::generate(&env);
        let a2 = Address::generate(&env);

        let event_id = client.create_event(
            &String::from_str(&env, "E"),
            &organizer,
            &1_000_000u64,
            &1_003_600u64,
            &String::from_str(&env, "X"),
            &0u32,
        );
        client.register(&event_id, &a1, &dummy_hash(&env, 1));
        client.register(&event_id, &a2, &dummy_hash(&env, 2));

        let shared_nonce = dummy_hash(&env, 99);
        client.register_nonce(&shared_nonce, &event_id, &NONCE_CHECKIN, &0u32);

        client.check_in(&event_id, &a1, &shared_nonce, &dummy_hash(&env, 3), &true);
        // Must panic — NonceAlreadyUsed
        client.check_in(&event_id, &a2, &shared_nonce, &dummy_hash(&env, 4), &true);
    }
}