//! Domain Lease Lifecycle & State Machine (GCP-08, ADR-0010, Issue #32).
//!
//! Enforces deterministic lifecycle states and monopoly protection for `.ark` public domains:
//! - **Active**: `now <= T_expire` (lease duration up to 365 days). Resolves normally (`in_grace_period = false`).
//! - **GracePeriod**: `T_expire < now <= T_expire + 14 days` (`14 * 86400s`).
//!   External resolutions return `in_grace_period = true` or `NXDOMAIN`, and renewals are restricted
//!   exclusively to the original owner `sender_key_id`. Renewals by other keys are rejected with
//!   `DnsError::GracePeriodRenewalUnauthorized`.
//! - **Expired**: `now > T_expire + 14 days`.
//!   The domain is evicted from active routing and becomes eligible for fresh registration by any keyholder
//!   with new PoW and L2 bond.
//!
//! Provides a pluggable `TimeProvider` interface allowing deterministic mock testing of lease progression
//! and expiration boundaries.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use subtle::ConstantTimeEq;

use crate::anti_sybil::validate_fqdn;
use crate::error::{DnsError, Result};
use crate::record::DomainRoutingRecord;
use crate::SovereignDnsTrie;

/// 14-day quarantine grace period in seconds: 14 * 24 * 3600 = 1,209,600 seconds.
pub const GRACE_PERIOD_SECS: u64 = 14 * 86_400;

/// Maximum domain lease duration: 365 days in seconds: 365 * 24 * 3600 = 31,536,000 seconds.
pub const MAX_LEASE_DURATION_SECS: u64 = 365 * 86_400;

/// Pluggable time provider for deterministic time abstraction.
pub trait TimeProvider: Send + Sync {
    /// Return the current UNIX timestamp in seconds.
    fn now_secs(&self) -> u64;
}

/// System clock implementation of `TimeProvider`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemTimeProvider;

impl TimeProvider for SystemTimeProvider {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Deterministic mock clock implementation of `TimeProvider` for testing.
#[derive(Debug)]
pub struct MockTimeProvider {
    now: AtomicU64,
}

impl MockTimeProvider {
    /// Create a new MockTimeProvider initialized with `initial_secs`.
    pub fn new(initial_secs: u64) -> Self {
        Self {
            now: AtomicU64::new(initial_secs),
        }
    }

    /// Set current time to `new_secs`.
    pub fn set_time(&self, new_secs: u64) {
        self.now.store(new_secs, Ordering::SeqCst);
    }

    /// Advance current time by `delta_secs`.
    pub fn advance(&self, delta_secs: u64) {
        self.now.fetch_add(delta_secs, Ordering::SeqCst);
    }
}

impl TimeProvider for MockTimeProvider {
    fn now_secs(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// Lifecycle state of a sovereign `.ark` domain lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainLeaseState {
    /// Domain lease is currently active (`now <= T_expire`). Resolves normally.
    Active,
    /// Domain lease is in 14-day quarantine grace period (`T_expire < now <= T_expire + 14d`).
    /// Resolves with `in_grace_period = true`, renewals restricted exclusively to original owner.
    GracePeriod,
    /// Domain lease is expired (`now > T_expire + 14d`).
    /// Evicted from routing, eligible for fresh registration by any keyholder.
    Expired,
}

impl DomainLeaseState {
    /// Compute the lease state for a given `expires_at` timestamp relative to `now`.
    pub fn compute(expires_at: u64, now: u64) -> Self {
        if now <= expires_at {
            DomainLeaseState::Active
        } else if now <= expires_at.saturating_add(GRACE_PERIOD_SECS) {
            DomainLeaseState::GracePeriod
        } else {
            DomainLeaseState::Expired
        }
    }
}

/// Domain Lease Lifecycle Engine.
///
/// Coordinates domain registrations, renewals, resolution, and expired record eviction
/// in accordance with GCP-08 and ADR-0010.
#[derive(Clone, Debug)]
pub struct LeaseLifecycleEngine<T: TimeProvider = SystemTimeProvider> {
    trie: Arc<SovereignDnsTrie>,
    time_provider: Arc<T>,
}

impl LeaseLifecycleEngine<SystemTimeProvider> {
    /// Create a new LeaseLifecycleEngine with the default SystemTimeProvider.
    pub fn new(trie: Arc<SovereignDnsTrie>) -> Self {
        Self {
            trie,
            time_provider: Arc::new(SystemTimeProvider),
        }
    }
}

impl<T: TimeProvider> LeaseLifecycleEngine<T> {
    /// Create a new LeaseLifecycleEngine with a custom or mock `TimeProvider`.
    pub fn with_time_provider(trie: Arc<SovereignDnsTrie>, time_provider: Arc<T>) -> Self {
        Self { trie, time_provider }
    }

    /// Returns a reference to the underlying time provider.
    pub fn time_provider(&self) -> &T {
        &self.time_provider
    }

    /// Returns a reference to the underlying trie.
    pub fn trie(&self) -> &Arc<SovereignDnsTrie> {
        &self.trie
    }

    /// Inspect the lifecycle state of a domain name in the trie.
    ///
    /// Returns `None` if the domain is not registered.
    pub fn state_of(&self, fqdn: &str) -> Option<DomainLeaseState> {
        let record = self.trie.get(fqdn)?;
        let now = self.time_provider.now_secs();
        Some(DomainLeaseState::compute(record.expires_at, now))
    }

    /// Resolve a domain name according to its lifecycle state:
    /// - **Active**: returns `Some(record)` with `in_grace_period = false`.
    /// - **GracePeriod**: returns `Some(record)` with `in_grace_period = true`.
    /// - **Expired**: returns `None` (NXDOMAIN) and triggers lazy eviction from active routing.
    /// - **Not found**: returns `None` (NXDOMAIN).
    pub fn resolve(&self, fqdn: &str) -> Result<Option<DomainRoutingRecord>> {
        let record_arc = match self.trie.get(fqdn) {
            Some(r) => r,
            None => return Ok(None),
        };

        let now = self.time_provider.now_secs();
        match DomainLeaseState::compute(record_arc.expires_at, now) {
            DomainLeaseState::Active => {
                let mut record = (*record_arc).clone();
                record.in_grace_period = false;
                Ok(Some(record))
            }
            DomainLeaseState::GracePeriod => {
                let mut record = (*record_arc).clone();
                record.in_grace_period = true;
                Ok(Some(record))
            }
            DomainLeaseState::Expired => {
                // Lazily evict expired record from active routing trie
                self.trie.remove(fqdn);
                Ok(None)
            }
        }
    }

    /// Direct lookup of a domain record from the trie without lifecycle state mutations.
    pub fn get_record(&self, fqdn: &str) -> Option<Arc<DomainRoutingRecord>> {
        self.trie.get(fqdn)
    }

    /// Register a new sovereign domain or reclaim an expired domain.
    ///
    /// Rules:
    /// - FQDN must be valid.
    /// - Lease duration must satisfy `now < expires_at <= now + MAX_LEASE_DURATION_SECS`.
    /// - If domain does not exist: accepted.
    /// - If existing domain is `Expired`: accepted (claimable by any keyholder with new PoW/bond).
    /// - If existing domain is `Active` or `GracePeriod`: rejected with `DnsError::DomainAlreadyActive`
    ///   or `DnsError::GracePeriodRenewalUnauthorized`.
    pub fn register(&self, mut record: DomainRoutingRecord) -> Result<()> {
        let canonical_fqdn = validate_fqdn(&record.fqdn)?;
        record.fqdn = canonical_fqdn;

        let now = self.time_provider.now_secs();
        Self::validate_lease_duration(now, record.expires_at)?;

        if let Some(existing) = self.trie.get(&record.fqdn) {
            let state = DomainLeaseState::compute(existing.expires_at, now);
            match state {
                DomainLeaseState::Active => {
                    return Err(DnsError::DomainAlreadyActive {
                        fqdn: record.fqdn.clone(),
                        current_owner: existing.owner_key_id,
                    });
                }
                DomainLeaseState::GracePeriod => {
                    let is_same_owner: bool = bool::from(existing.owner_key_id.ct_eq(&record.owner_key_id));
                    if !is_same_owner {
                        return Err(DnsError::GracePeriodRenewalUnauthorized {
                            fqdn: record.fqdn.clone(),
                            current_owner: existing.owner_key_id,
                            attempted_by: record.owner_key_id,
                        });
                    }
                    // Same owner attempting register during grace period is treated as renewal
                }
                DomainLeaseState::Expired => {
                    // Expired domain: previous owner monopoly released, claimable by any valid peer!
                }
            }
        }

        record.in_grace_period = false;
        self.trie.insert(record);
        Ok(())
    }

    /// Renew an existing domain lease.
    ///
    /// Rules:
    /// - Lease duration must satisfy `now < expires_at <= now + MAX_LEASE_DURATION_SECS`.
    /// - If domain does not exist or is `Expired`: returns `DnsError::InvalidRecord("domain not registered or already expired")`.
    /// - If domain is `Active` or `GracePeriod`:
    ///   - Must be the original owner `sender_key_id` (`owner_key_id`).
    ///   - If another keyholder attempts renewal during GracePeriod: returns `DnsError::GracePeriodRenewalUnauthorized`.
    ///   - If another keyholder attempts renewal while Active: returns `DnsError::UnauthorizedRenewal`.
    pub fn renew(&self, mut record: DomainRoutingRecord) -> Result<()> {
        let canonical_fqdn = validate_fqdn(&record.fqdn)?;
        record.fqdn = canonical_fqdn;

        let now = self.time_provider.now_secs();
        Self::validate_lease_duration(now, record.expires_at)?;

        let existing = self
            .trie
            .get(&record.fqdn)
            .ok_or_else(|| DnsError::InvalidRecord(format!("Domain '{}' is not registered", record.fqdn)))?;

        let state = DomainLeaseState::compute(existing.expires_at, now);
        match state {
            DomainLeaseState::Active => {
                let is_same_owner: bool = bool::from(existing.owner_key_id.ct_eq(&record.owner_key_id));
                if !is_same_owner {
                    return Err(DnsError::UnauthorizedRenewal {
                        fqdn: record.fqdn.clone(),
                        current_owner: existing.owner_key_id,
                        attempted_by: record.owner_key_id,
                    });
                }
            }
            DomainLeaseState::GracePeriod => {
                let is_same_owner: bool = bool::from(existing.owner_key_id.ct_eq(&record.owner_key_id));
                if !is_same_owner {
                    return Err(DnsError::GracePeriodRenewalUnauthorized {
                        fqdn: record.fqdn.clone(),
                        current_owner: existing.owner_key_id,
                        attempted_by: record.owner_key_id,
                    });
                }
            }
            DomainLeaseState::Expired => {
                // Past 14-day grace period, the lease has expired and monopoly is gone.
                // Must be registered as a fresh registration, not renewed.
                return Err(DnsError::InvalidRecord(format!(
                    "Domain '{}' lease has expired past 14-day grace period and must be freshly registered",
                    record.fqdn
                )));
            }
        }

        record.in_grace_period = false;
        self.trie.insert(record);
        Ok(())
    }

    /// Convenience method to register a sovereign domain from a `ValidatedDnsClaim`.
    pub fn register_claim(
        &self,
        claim: &crate::anti_sybil::ValidatedDnsClaim,
        target_peer_id: [u8; 32],
        routing_addrs: Vec<String>,
        ech_public_key: Vec<u8>,
    ) -> Result<()> {
        let record = DomainRoutingRecord {
            fqdn: claim.fqdn.clone(),
            owner_key_id: claim.owner_key_id,
            target_peer_id,
            routing_addrs,
            expires_at: claim.lease_epoch,
            in_grace_period: false,
            epoch_timestamp: self.time_provider.now_secs(),
            ech_public_key,
        };
        self.register(record)
    }

    /// Convenience method to renew a sovereign domain from a `ValidatedDnsClaim`.
    pub fn renew_claim(
        &self,
        claim: &crate::anti_sybil::ValidatedDnsClaim,
        target_peer_id: [u8; 32],
        routing_addrs: Vec<String>,
        ech_public_key: Vec<u8>,
    ) -> Result<()> {
        let record = DomainRoutingRecord {
            fqdn: claim.fqdn.clone(),
            owner_key_id: claim.owner_key_id,
            target_peer_id,
            routing_addrs,
            expires_at: claim.lease_epoch,
            in_grace_period: false,
            epoch_timestamp: self.time_provider.now_secs(),
            ech_public_key,
        };
        self.renew(record)
    }

    /// Sweep and evict all expired domains past the 14-day grace window.
    ///
    /// Returns the list of evicted routing records.
    pub fn evict_expired(&self) -> Vec<Arc<DomainRoutingRecord>> {
        let now = self.time_provider.now_secs();
        let all_records = self.trie.all_records();
        let mut evicted = Vec::new();

        for record in all_records {
            if DomainLeaseState::compute(record.expires_at, now) == DomainLeaseState::Expired {
                if let Some(removed) = self.trie.remove(&record.fqdn) {
                    evicted.push(removed);
                }
            }
        }

        evicted
    }

    fn validate_lease_duration(now: u64, expires_at: u64) -> Result<()> {
        if expires_at <= now {
            return Err(DnsError::InvalidLeaseDuration(format!(
                "Lease expiration ({}) must be in the future (current time: {})",
                expires_at, now
            )));
        }

        let duration = expires_at - now;
        if duration > MAX_LEASE_DURATION_SECS {
            return Err(DnsError::InvalidLeaseDuration(format!(
                "Lease duration ({} seconds) exceeds maximum allowed duration of 365 days ({} seconds)",
                duration, MAX_LEASE_DURATION_SECS
            )));
        }

        Ok(())
    }
}
