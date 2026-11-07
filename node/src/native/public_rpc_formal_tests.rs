//! Actual per-node discovery checks complement the generated pure decision table.
use super::*;

#[test]
fn public_rpc_formal_catalog_matches_registered_available_dispatch() {
    for policy in ["safe", "pool", "unsafe", "public-submit"] {
        let temp = tempfile::tempdir().unwrap();
        let node = NativeNode::open(super::tests::test_config(
            temp.path(),
            0x207f_ffff,
            policy,
            false,
        ))
        .unwrap();
        let catalog = dispatch_rpc_method(&node, "rpc_methods", json!([])).unwrap();
        let listed: BTreeSet<String> = catalog["methods"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            listed.len(),
            catalog["methods"].as_array().unwrap().len(),
            "duplicate catalog entry under {policy}"
        );
        let mut candidates = native_rpc_methods(RpcMethodPolicy::Unsafe);
        candidates.extend([
            "unknown_public_rpc_method",
            "hegemon_developmentPendingActionChunk",
        ]);
        for method in candidates {
            assert_eq!(
                listed.contains(method),
                rpc_method_available(&node, method),
                "discovery/dispatch availability mismatch for {policy} {method}"
            );
            if !rpc_method_available(&node, method) {
                let result = dispatch_rpc_method(&node, method, json!([]));
                assert!(
                    result.is_err() || result.as_ref().is_ok_and(|v| v["success"] == false),
                    "unavailable method did not refuse: {policy} {method}"
                );
            }
        }
        // This node has no controlled-asset capability. An unsafe policy cannot
        // turn the absence of source authority into a callable asset route.
        for method in ["hegemon_assetSnapshot", "hegemon_assetRecoverySnapshot"] {
            assert!(!listed.contains(method));
        }
    }
}

#[test]
fn public_rpc_formal_effective_surface_is_safe_plus_submit() {
    let safe_temp = tempfile::tempdir().unwrap();
    let public_temp = tempfile::tempdir().unwrap();
    let safe = NativeNode::open(super::tests::test_config(
        safe_temp.path(),
        0x207f_ffff,
        "safe",
        false,
    ))
    .unwrap();
    let public = NativeNode::open(super::tests::test_config(
        public_temp.path(),
        0x207f_ffff,
        "public-submit",
        false,
    ))
    .unwrap();
    let catalog = |node: &Arc<NativeNode>| -> BTreeSet<String> {
        dispatch_rpc_method(node, "rpc_methods", json!([])).unwrap()["methods"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };
    let mut expected = catalog(&safe);
    expected.insert("hegemon_submitAction".into());
    assert_eq!(catalog(&public), expected);
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LeanRpcOwnershipCase {
    kind: String,
    expected_active: Vec<usize>,
    expected_submissions: Vec<usize>,
}

/// Exercise real non-cloneable production permits, Tokio blocking workers and
/// production response-body ownership. Lean supplies expected snapshots; Rust
/// performs the actual lifecycle instead of reimplementing the Lean transitions.
pub(super) async fn verify_lean_rpc_ownership_case(case: &LeanRpcOwnershipCase) {
    use super::public_admission::{
        hold_public_response_permit, PublicRpcAdmission, PublicRpcLimits,
    };
    use futures::StreamExt;
    let admission = Arc::new(
        PublicRpcAdmission::new(PublicRpcLimits {
            request_concurrency: 1,
            submission_concurrency: 1,
            ..Default::default()
        })
        .unwrap(),
    );
    let permit = admission.try_request().unwrap();
    let submission = if case.kind.starts_with("worker_") {
        Some(admission.try_submit().unwrap())
    } else {
        None
    };
    let mut observed = vec![admission.snapshot().requests_in_flight];
    let mut observed_submissions = vec![admission.snapshot().submissions_in_flight];
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(0);
    match case.kind.as_str() {
        "worker_cancel" | "worker_failure" => {
            struct Completion(Option<tokio::sync::oneshot::Sender<()>>);
            impl Drop for Completion {
                fn drop(&mut self) {
                    if let Some(done) = self.0.take() {
                        let _ = done.send(());
                    }
                }
            }
            let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
            let fail = case.kind == "worker_failure";
            let worker = tokio::task::spawn_blocking(move || {
                // Reverse drop order makes the completion signal witness that
                // the real permit was already dropped, including during panic.
                let _completed = Completion(Some(completed_tx));
                let _permit = permit;
                let _submission = submission;
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                if fail {
                    panic!("controlled public RPC verifier failure");
                }
            });
            started_rx.await.unwrap();
            observed.push(admission.snapshot().requests_in_flight);
            observed_submissions.push(admission.snapshot().submissions_in_flight);
            let waiter = tokio::spawn(async move { worker.await });
            waiter.abort();
            assert!(waiter.await.unwrap_err().is_cancelled());
            observed.push(admission.snapshot().requests_in_flight);
            observed_submissions.push(admission.snapshot().submissions_in_flight);
            assert!(
                admission.try_request().is_err(),
                "cancellation released a running worker"
            );
            release_tx.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), completed_rx)
                .await
                .unwrap()
                .unwrap();
            observed.push(admission.snapshot().requests_in_flight);
            observed_submissions.push(admission.snapshot().submissions_in_flight);
        }
        "response_drop" | "response_exhaust" => {
            let worker = tokio::task::spawn_blocking(move || {
                let permit = permit;
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                permit
            });
            started_rx.await.unwrap();
            observed.push(admission.snapshot().requests_in_flight);
            observed_submissions.push(admission.snapshot().submissions_in_flight);
            release_tx.send(()).unwrap();
            let permit = worker.await.unwrap();
            let response = hold_public_response_permit(
                Response::new(axum::body::Body::from(vec![7u8; 48 * 1024])),
                permit,
            );
            observed.push(admission.snapshot().requests_in_flight);
            observed_submissions.push(admission.snapshot().submissions_in_flight);
            let mut stream = response.into_body().into_data_stream();
            assert!(!stream.next().await.unwrap().unwrap().is_empty());
            observed.push(admission.snapshot().requests_in_flight);
            observed_submissions.push(admission.snapshot().submissions_in_flight);
            assert!(
                admission.try_request().is_err(),
                "partial body consumption released capacity"
            );
            if case.kind == "response_exhaust" {
                while let Some(chunk) = stream.next().await {
                    chunk.unwrap();
                }
            }
            drop(stream);
            observed.push(admission.snapshot().requests_in_flight);
            observed_submissions.push(admission.snapshot().submissions_in_flight);
        }
        other => panic!("unknown Lean ownership trace {other}"),
    }
    assert_eq!(
        observed, case.expected_active,
        "{} production ownership trace",
        case.kind
    );
    assert_eq!(
        observed_submissions, case.expected_submissions,
        "{} submission ownership trace",
        case.kind
    );
    assert_eq!(admission.snapshot().submissions_in_flight, 0);
    // A completed owner returns exactly one slot: a fresh owner fits, a second
    // cannot fit. This detects a leaked reservation or a doubled release.
    let fresh = admission.try_request().unwrap();
    assert!(admission.try_request().is_err());
    drop(fresh);
    assert_eq!(admission.snapshot().requests_in_flight, 0);
}
