//! Finite admission for the explicitly selected public RPC service.
//!
//! A reservation belongs to the work, not its HTTP response future. Move the
//! request and submission reservations into the blocking worker before spawning
//! it; dropping/aborting the waiter cannot cancel that worker or release its slot.
//! There is no waiting queue and no asserted verifier wall-clock cutoff.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use parking_lot::Mutex;

const CLIENT_WINDOW: Duration = Duration::from_secs(60);

/// These limits apply only to the explicitly selected public-submit listener.
#[derive(Clone, Debug, clap::Args)]
pub struct PublicRpcLimits {
    /// JSON-RPC method calls per transport IP in a fixed 60-second window.
    #[arg(long = "rpc-public-requests-per-minute", default_value_t = 60)]
    pub requests_per_minute: u32,
    /// Submission attempts per transport IP in a fixed 60-second window.
    #[arg(long = "rpc-public-submissions-per-minute", default_value_t = 6)]
    pub submissions_per_minute: u32,
    /// Maximum retained transport-IP rate-limit entries; new clients fail closed when full.
    #[arg(long = "rpc-public-client-capacity", default_value_t = 1024)]
    pub client_capacity: usize,
    /// Expire idle client entries before admission (at least 60 seconds).
    #[arg(long = "rpc-public-client-ttl-secs", default_value_t = 600)]
    pub client_ttl_secs: u64,
    /// Concurrent public HTTP body/dispatch workers; no waiting queue.
    #[arg(long = "rpc-public-request-concurrency", default_value_t = 4)]
    pub request_concurrency: usize,
    /// Concurrent public submissions, separate from peer/local/mining verifier slots.
    #[arg(long = "rpc-public-submission-concurrency", default_value_t = 1)]
    pub submission_concurrency: usize,
}

impl Default for PublicRpcLimits {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            submissions_per_minute: 6,
            client_capacity: 1024,
            client_ttl_secs: 600,
            request_concurrency: 4,
            submission_concurrency: 1,
        }
    }
}

impl PublicRpcLimits {
    pub fn validate(&self) -> Result<()> {
        if !(1..=6000).contains(&self.requests_per_minute)
            || !(1..=60).contains(&self.submissions_per_minute)
            || !(1..=65536).contains(&self.client_capacity)
            || !(60..=3600).contains(&self.client_ttl_secs)
            || !(1..=64).contains(&self.request_concurrency)
            || !(1..=4).contains(&self.submission_concurrency)
            || self.submission_concurrency > self.request_concurrency
        {
            return Err(anyhow!(
                "public RPC limits require requests/minute 1..=6000, submissions/minute 1..=60, clients 1..=65536, idle TTL 60..=3600 seconds, requests 1..=64, and submissions 1..=min(4, requests)"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicAdmissionRejection {
    ClientRate,
    ClientCapacity,
    RequestCapacity,
    SubmissionCapacity,
    RequestRate,
}

impl PublicAdmissionRejection {
    pub(crate) fn code(self) -> i64 {
        match self {
            Self::ClientRate => -32070,
            Self::ClientCapacity => -32071,
            Self::RequestCapacity => -32072,
            Self::SubmissionCapacity => -32073,
            Self::RequestRate => -32075,
        }
    }

    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::ClientRate => "public submission rate limit exceeded",
            Self::ClientCapacity => "public submission client table at capacity",
            Self::RequestCapacity => "public RPC request capacity exhausted",
            Self::SubmissionCapacity => "public submission verification capacity exhausted",
            Self::RequestRate => "public RPC request rate limit exceeded",
        }
    }
}

/// Method permission never grants unrelated protocol-action authority. The
/// ordinary public carrier uses the existing inline PrivateSpend action only;
/// its unchanged source and private-mode restrictions are checked downstream.
pub(crate) fn public_submit_action_route_allowed(family: u16, action: u16) -> bool {
    family == super::FAMILY_SHIELDED_POOL && action == super::PRIVATE_SPEND_ACTION_ID
}

/// Pure transitions used by the actual counter updates and Lean conformance.
pub(crate) fn public_capacity_reserve(active: usize, limit: usize) -> Option<usize> {
    if active < limit {
        active.checked_add(1)
    } else {
        None
    }
}

pub(crate) fn public_capacity_release(active: usize) -> Option<usize> {
    active.checked_sub(1)
}

pub(crate) fn public_client_charge(used: u32, limit: u32, expired: bool) -> Option<u32> {
    let used = if expired { 0 } else { used };
    if used < limit {
        used.checked_add(1)
    } else {
        None
    }
}

pub(crate) fn public_client_table_insert_allowed(
    retained: usize,
    capacity: usize,
    known: bool,
) -> bool {
    known || retained < capacity
}

/// IPv4 and its IPv4-mapped IPv6 form use one bucket. Ordinary IPv6 addresses
/// retain their full 128 bits. Ports and forwarding headers are never identity.
pub(crate) fn normalize_public_client(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        IpAddr::V4(_) => ip,
    }
}

struct Capacity {
    limit: usize,
    active: Mutex<usize>,
}

impl Capacity {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            active: Mutex::new(0),
        })
    }

    fn reserve(self: &Arc<Self>) -> Option<Reservation> {
        let mut active = self.active.lock();
        *active = public_capacity_reserve(*active, self.limit)?;
        Some(Reservation {
            capacity: Arc::clone(self),
        })
    }
}

/// Deliberately has no Clone or explicit release method: exactly one owner
/// returns exactly one slot on drop, including unwinding after worker failure.
struct Reservation {
    capacity: Arc<Capacity>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut active = self.capacity.active.lock();
        *active = public_capacity_release(*active)
            .expect("a live public RPC reservation owns one capacity slot");
    }
}

pub(crate) struct PublicRequestPermit {
    _reservation: Reservation,
}

/// Keep a completed request's reservation while its serialized body is consumed
/// or abandoned. Small frames allow HTTP transport backpressure to stop polling
/// without first taking the complete (up to 8 MiB) body. This is body-lifetime
/// accounting, not a bound on OS/socket buffers or a delivery acknowledgement.
pub(crate) fn hold_public_response_permit(
    response: axum::response::Response,
    permit: PublicRequestPermit,
) -> axum::response::Response {
    use futures::StreamExt;
    let (parts, body) = response.into_parts();
    let stream = futures::stream::unfold(
        (body.into_data_stream(), None::<axum::body::Bytes>, permit),
        |(mut stream, pending, permit)| async move {
            let chunk = match pending {
                Some(bytes) => Some(Ok(bytes)),
                None => stream.next().await,
            };
            match chunk {
                Some(Ok(mut bytes)) => {
                    let head = bytes.split_to(bytes.len().min(16 * 1024));
                    let pending = (!bytes.is_empty()).then_some(bytes);
                    Some((Ok::<_, axum::Error>(head), (stream, pending, permit)))
                }
                Some(Err(error)) => Some((Err(error), (stream, None, permit))),
                None => None,
            }
        },
    );
    axum::response::Response::from_parts(parts, axum::body::Body::from_stream(stream))
}

pub(crate) struct PublicSubmissionPermit {
    reservation: Reservation,
    // A submission token can move into one worker, but references to it cannot
    // be shared across workers to multiply admitted synchronous verification.
    _exclusive: std::marker::PhantomData<std::cell::Cell<()>>,
}

struct ClientWindow {
    window_started: Instant,
    last_seen: Instant,
    submissions_used: u32,
    requests_used: u32,
}

pub(crate) struct PublicRpcAdmission {
    limits: PublicRpcLimits,
    requests: Arc<Capacity>,
    submissions: Arc<Capacity>,
    clients: Mutex<BTreeMap<IpAddr, ClientWindow>>,
}

impl PublicRpcAdmission {
    pub(crate) fn new(limits: PublicRpcLimits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            requests: Capacity::new(limits.request_concurrency),
            submissions: Capacity::new(limits.submission_concurrency),
            clients: Mutex::new(BTreeMap::new()),
            limits,
        })
    }

    pub(crate) fn try_request(
        &self,
    ) -> std::result::Result<PublicRequestPermit, PublicAdmissionRejection> {
        self.requests
            .reserve()
            .map(|reservation| PublicRequestPermit {
                _reservation: reservation,
            })
            .ok_or(PublicAdmissionRejection::RequestCapacity)
    }

    pub(crate) fn try_submit(
        &self,
    ) -> std::result::Result<PublicSubmissionPermit, PublicAdmissionRejection> {
        self.submissions
            .reserve()
            .map(|reservation| PublicSubmissionPermit {
                reservation,
                _exclusive: std::marker::PhantomData,
            })
            .ok_or(PublicAdmissionRejection::SubmissionCapacity)
    }

    pub(crate) fn owns_submission(&self, permit: &PublicSubmissionPermit) -> bool {
        Arc::ptr_eq(&self.submissions, &permit.reservation.capacity)
    }

    pub(crate) fn charge_submission(
        &self,
        ip: IpAddr,
    ) -> std::result::Result<(), PublicAdmissionRejection> {
        self.charge_client_at(ip, Instant::now(), true)
    }

    pub(crate) fn charge_request(
        &self,
        ip: IpAddr,
    ) -> std::result::Result<(), PublicAdmissionRejection> {
        self.charge_client_at(ip, Instant::now(), false)
    }

    #[cfg(test)]
    fn charge_submission_at(
        &self,
        ip: IpAddr,
        now: Instant,
    ) -> std::result::Result<(), PublicAdmissionRejection> {
        self.charge_client_at(ip, now, true)
    }

    fn charge_client_at(
        &self,
        ip: IpAddr,
        now: Instant,
        submission: bool,
    ) -> std::result::Result<(), PublicAdmissionRejection> {
        let ip = normalize_public_client(ip);
        let mut clients = self.clients.lock();
        let ttl = Duration::from_secs(self.limits.client_ttl_secs);
        clients.retain(|_, client| now.saturating_duration_since(client.last_seen) < ttl);
        if !public_client_table_insert_allowed(
            clients.len(),
            self.limits.client_capacity,
            clients.contains_key(&ip),
        ) {
            return Err(PublicAdmissionRejection::ClientCapacity);
        }
        let client = clients.entry(ip).or_insert(ClientWindow {
            window_started: now,
            last_seen: now,
            submissions_used: 0,
            requests_used: 0,
        });
        let expired = now.saturating_duration_since(client.window_started) >= CLIENT_WINDOW;
        client.last_seen = now;
        if expired {
            client.window_started = now;
            client.submissions_used = 0;
            client.requests_used = 0;
        }
        let (used, limit, error) = if submission {
            (
                &mut client.submissions_used,
                self.limits.submissions_per_minute,
                PublicAdmissionRejection::ClientRate,
            )
        } else {
            (
                &mut client.requests_used,
                self.limits.requests_per_minute,
                PublicAdmissionRejection::RequestRate,
            )
        };
        *used = public_client_charge(*used, limit, expired).ok_or(error)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> PublicAdmissionSnapshot {
        PublicAdmissionSnapshot {
            requests_in_flight: *self.requests.active.lock(),
            submissions_in_flight: *self.submissions.active.lock(),
            clients: self.clients.lock().len(),
        }
    }
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PublicAdmissionSnapshot {
    pub(crate) requests_in_flight: usize,
    pub(crate) submissions_in_flight: usize,
    pub(crate) clients: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admission() -> PublicRpcAdmission {
        PublicRpcAdmission::new(PublicRpcLimits {
            requests_per_minute: 60,
            submissions_per_minute: 2,
            client_capacity: 2,
            client_ttl_secs: 60,
            request_concurrency: 2,
            submission_concurrency: 1,
        })
        .unwrap()
    }

    #[test]
    fn public_counter_transitions_fail_closed_at_bounds() {
        assert_eq!(public_capacity_reserve(0, 0), None);
        assert_eq!(public_capacity_reserve(1, 2), Some(2));
        assert_eq!(public_capacity_reserve(2, 2), None);
        assert_eq!(public_capacity_reserve(usize::MAX, usize::MAX), None);
        assert_eq!(public_capacity_release(0), None);
        assert_eq!(public_capacity_release(2), Some(1));
        assert_eq!(public_client_charge(u32::MAX, u32::MAX, false), None);
        assert_eq!(public_client_charge(u32::MAX, 1, true), Some(1));
        assert_eq!(public_client_charge(0, 0, true), None);
    }

    #[test]
    fn public_clients_are_normalized_counted_and_expired_without_eviction() {
        let admission = admission();
        let now = Instant::now();
        let ip = "192.0.2.1".parse().unwrap();
        let mapped = "::ffff:192.0.2.1".parse().unwrap();
        let second = "2001:db8::1".parse().unwrap();
        let third = "198.51.100.1".parse().unwrap();
        admission.charge_submission_at(ip, now).unwrap();
        admission.charge_submission_at(mapped, now).unwrap();
        assert_eq!(
            admission.charge_submission_at(ip, now),
            Err(PublicAdmissionRejection::ClientRate)
        );
        assert_eq!(admission.snapshot().clients, 1);
        admission.charge_submission_at(second, now).unwrap();
        assert_eq!(
            admission.charge_submission_at(third, now),
            Err(PublicAdmissionRejection::ClientCapacity)
        );
        assert_eq!(admission.snapshot().clients, 2);
        admission
            .charge_submission_at(third, now + Duration::from_secs(60))
            .unwrap();
        assert_eq!(admission.snapshot().clients, 1);
    }

    #[test]
    fn public_rate_window_does_not_reset_on_denial_or_other_client() {
        let admission = admission();
        let now = Instant::now();
        let ip = "192.0.2.1".parse().unwrap();
        admission.charge_submission_at(ip, now).unwrap();
        admission
            .charge_submission_at(ip, now + Duration::from_secs(58))
            .unwrap();
        assert_eq!(
            admission.charge_submission_at(ip, now + Duration::from_secs(59)),
            Err(PublicAdmissionRejection::ClientRate)
        );
        admission
            .charge_submission_at(ip, now + Duration::from_secs(60))
            .unwrap();
    }

    #[test]
    fn public_reservations_have_one_owner_and_separate_capacity() {
        let other = admission();
        let admission = admission();
        let request = admission.try_request().unwrap();
        let submission = admission.try_submit().unwrap();
        assert!(admission.owns_submission(&submission));
        assert!(!other.owns_submission(&submission));
        assert!(matches!(
            admission.try_submit(),
            Err(PublicAdmissionRejection::SubmissionCapacity)
        ));
        assert_eq!(admission.snapshot().requests_in_flight, 1);
        drop(submission);
        assert_eq!(admission.snapshot().submissions_in_flight, 0);
        assert_eq!(admission.snapshot().requests_in_flight, 1);
        drop(request);
        assert_eq!(admission.snapshot().requests_in_flight, 0);
    }

    #[test]
    fn public_read_and_submission_counters_are_separate_but_share_bounded_clients() {
        let admission = PublicRpcAdmission::new(PublicRpcLimits {
            requests_per_minute: 2,
            submissions_per_minute: 1,
            client_capacity: 1,
            ..PublicRpcLimits::default()
        })
        .unwrap();
        let now = Instant::now();
        let ip = "192.0.2.1".parse().unwrap();
        admission.charge_client_at(ip, now, false).unwrap();
        admission.charge_client_at(ip, now, false).unwrap();
        assert_eq!(
            admission.charge_client_at(ip, now, false),
            Err(PublicAdmissionRejection::RequestRate)
        );
        admission.charge_client_at(ip, now, true).unwrap();
        assert_eq!(
            admission.charge_client_at(ip, now, true),
            Err(PublicAdmissionRejection::ClientRate)
        );
        assert_eq!(admission.snapshot().clients, 1);
        admission
            .charge_client_at(ip, now + CLIENT_WINDOW, false)
            .unwrap();
        admission
            .charge_client_at(ip, now + CLIENT_WINDOW, true)
            .unwrap();
    }

    #[test]
    fn public_parallel_reservation_attempts_never_exceed_capacity() {
        let admission = Arc::new(admission());
        let start = Arc::new(std::sync::Barrier::new(17));
        let held = Arc::new(std::sync::Barrier::new(17));
        let release = Arc::new(std::sync::Barrier::new(17));
        let mut workers = Vec::new();
        for _ in 0..16 {
            let admission = Arc::clone(&admission);
            let start = Arc::clone(&start);
            let held = Arc::clone(&held);
            let release = Arc::clone(&release);
            workers.push(std::thread::spawn(move || {
                start.wait();
                let permit = admission.try_submit().ok();
                held.wait();
                release.wait();
                drop(permit);
            }));
        }
        start.wait();
        held.wait();
        assert_eq!(admission.snapshot().submissions_in_flight, 1);
        release.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(admission.snapshot().submissions_in_flight, 0);
    }

    #[test]
    fn public_production_lane_never_borrows_local_or_shared_verifier_capacity() {
        use super::super::{tests::test_config, NativeNode};
        let temp = tempfile::tempdir().unwrap();
        let node = NativeNode::open(test_config(
            temp.path(),
            0x207f_ffff,
            "public-submit",
            false,
        ))
        .unwrap();
        let public = node.public_rpc_admission.try_submit().unwrap();
        let local = Arc::clone(&node.local_pending_proof_admission_semaphore)
            .try_acquire_owned()
            .unwrap();
        let shared = Arc::clone(&node.pending_proof_admission_semaphore)
            .try_acquire_many_owned(3)
            .unwrap();
        assert!(node
            .acquire_pending_verifier_lane(Some(&public))
            .unwrap()
            .is_none());
        assert!(node
            .acquire_pending_verifier_lane(None)
            .unwrap_err()
            .to_string()
            .contains("local pending"));
        assert_eq!(
            node.local_pending_proof_admission_semaphore
                .available_permits(),
            0
        );
        assert_eq!(
            node.pending_proof_admission_semaphore.available_permits(),
            0
        );
        let foreign = admission().try_submit().unwrap();
        assert!(node
            .acquire_pending_verifier_lane(Some(&foreign))
            .unwrap_err()
            .to_string()
            .contains("another node"));
        drop(local);
        // Failure to obtain shared capacity must release the local permit.
        assert!(node
            .acquire_pending_verifier_lane(None)
            .unwrap_err()
            .to_string()
            .contains("pending proof verifier at capacity"));
        assert_eq!(
            node.local_pending_proof_admission_semaphore
                .available_permits(),
            1
        );
        drop(shared);
        let local = node.acquire_pending_verifier_lane(None).unwrap().unwrap();
        assert_eq!(
            node.local_pending_proof_admission_semaphore
                .available_permits(),
            0
        );
        assert_eq!(
            node.pending_proof_admission_semaphore.available_permits(),
            2
        );
        assert!(node
            .acquire_pending_verifier_lane(Some(&public))
            .unwrap()
            .is_none());
        drop(local);
        assert_eq!(
            node.local_pending_proof_admission_semaphore
                .available_permits(),
            1
        );
        assert_eq!(
            node.pending_proof_admission_semaphore.available_permits(),
            3
        );
    }

    #[tokio::test]
    async fn public_response_body_retains_its_slot_until_consumed_or_dropped() {
        use futures::StreamExt;
        let admission = admission();
        let response = axum::response::Response::new(axum::body::Body::from(vec![7u8; 48 * 1024]));
        let response = hold_public_response_permit(response, admission.try_request().unwrap());
        let mut stream = response.into_body().into_data_stream();
        assert_eq!(stream.next().await.unwrap().unwrap().len(), 16 * 1024);
        assert_eq!(admission.snapshot().requests_in_flight, 1);
        drop(stream);
        assert_eq!(admission.snapshot().requests_in_flight, 0);
        let response = axum::response::Response::new(axum::body::Body::from(vec![9u8; 48 * 1024]));
        let response = hold_public_response_permit(response, admission.try_request().unwrap());
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap()
                .as_ref(),
            &[9u8; 48 * 1024]
        );
        assert_eq!(admission.snapshot().requests_in_flight, 0);
    }

    #[tokio::test]
    async fn public_blocking_worker_keeps_reservations_after_waiter_abort() {
        let admission = Arc::new(admission());
        let worker_admission = Arc::clone(&admission);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = std::sync::mpsc::channel();
        let waiter = tokio::spawn(async move {
            let request = worker_admission.try_request().unwrap();
            let submission = worker_admission.try_submit().unwrap();
            tokio::task::spawn_blocking(move || {
                let _request = request;
                let _submission = submission;
                started_tx.send(()).unwrap();
                finish_rx.recv().unwrap();
                panic!("controlled worker failure after cancellation");
            })
            .await
        });
        started_rx.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert_eq!(admission.snapshot().requests_in_flight, 1);
        assert_eq!(admission.snapshot().submissions_in_flight, 1);
        assert!(matches!(
            admission.try_submit(),
            Err(PublicAdmissionRejection::SubmissionCapacity)
        ));
        finish_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let snapshot = admission.snapshot();
                if snapshot.submissions_in_flight == 0 && snapshot.requests_in_flight == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(admission.snapshot().requests_in_flight, 0);
    }
}
