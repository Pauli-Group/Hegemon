//! Real loopback HTTP regressions for the opt-in public listener.
//!
//! These tests use disposable legacy state. They prove transport/admission and
//! fail-closed behavior, not a successful authorized PrivateSpend lifecycle.
//! The lock-controlled workers below never fabricate a proof or source authority.

use super::*;
use std::collections::BTreeSet;
use tokio::io::AsyncWriteExt;

struct HttpRpc {
    _temp: tempfile::TempDir,
    node: Arc<NativeNode>,
    addr: SocketAddr,
    client: reqwest::Client,
    server: tokio::task::JoinHandle<()>,
}

impl HttpRpc {
    async fn open(
        policy: &str,
        limits: public_admission::PublicRpcLimits,
        cors: Option<&str>,
    ) -> Self {
        let temp = tempfile::tempdir().expect("isolated RPC directory");
        let mut config = tests::test_config(temp.path(), 0x207f_ffff, policy, false);
        config.public_rpc_limits = limits;
        config.rpc_cors = cors.map(str::to_owned);
        let node = NativeNode::open(config).expect("isolated native node");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener");
        let addr = listener.local_addr().unwrap();
        let app = native_rpc_router(Arc::clone(&node));
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("RPC server");
        });
        Self {
            _temp: temp,
            node,
            addr,
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            server,
        }
    }

    fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    async fn post(&self, value: Value) -> Value {
        let response = self
            .client
            .post(self.url())
            .json(&value)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        response.json().await.unwrap()
    }

    async fn catalog(&self) -> BTreeSet<String> {
        self.post(call(1, "rpc_methods", json!([]))).await["result"]["methods"]
            .as_array()
            .unwrap()
            .iter()
            .map(|method| method.as_str().unwrap().to_owned())
            .collect()
    }

    async fn raw_post(&self, value: Value) -> tokio::net::TcpStream {
        let mut socket = tokio::net::TcpStream::connect(self.addr).await.unwrap();
        let body = serde_json::to_vec(&value).unwrap();
        let head = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.addr,
            body.len()
        );
        socket.write_all(head.as_bytes()).await.unwrap();
        socket.write_all(&body).await.unwrap();
        socket.flush().await.unwrap();
        socket
    }
}

impl Drop for HttpRpc {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn call(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn private_spend_request() -> Value {
    // Correct outer route, deliberately no proof. Existing network/source and
    // canonical framing checks must reject this on disposable legacy state.
    json!({
        "family_id": 1, "action_id": 15,
        "binding_circuit": 12, "binding_crypto": 7,
        "public_args": "", "new_nullifiers": []
    })
}

fn high_limits() -> public_admission::PublicRpcLimits {
    public_admission::PublicRpcLimits {
        submissions_per_minute: 60,
        ..Default::default()
    }
}

fn snapshot_db(node: &NativeNode) -> BTreeMap<Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>> {
    node.db
        .tree_names()
        .into_iter()
        .map(|name| {
            let tree = node.db.open_tree(&name).unwrap();
            let rows = tree
                .iter()
                .map(|row| {
                    let (key, value) = row.unwrap();
                    (key.to_vec(), value.to_vec())
                })
                .collect();
            (name.to_vec(), rows)
        })
        .collect()
}

async fn wait_counts(node: &NativeNode, requests: usize, submissions: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let state = node.public_rpc_admission.snapshot();
            if state.requests_in_flight == requests && state.submissions_in_flight == submissions {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("public admission reached expected worker counts");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_catalog_is_safe_plus_submit_and_privileged_calls_do_not_mutate() {
    let safe = HttpRpc::open("safe", high_limits(), None).await;
    let public = HttpRpc::open("public-submit", high_limits(), None).await;
    let safe_methods = safe.catalog().await;
    let public_methods = public.catalog().await;
    let mut expected = safe_methods.clone();
    assert!(expected.insert("hegemon_submitAction".into()));
    assert_eq!(public_methods, expected);
    let before = snapshot_db(&public.node);
    for (id, method) in [
        "hegemon_startMining",
        "hegemon_stopMining",
        "hegemon_poolWork",
        "hegemon_compactJob",
        "hegemon_submitPoolShare",
        "hegemon_submitCompactSolution",
        "hegemon_peerGraph",
        "hegemon_peerList",
        "hegemon_exportBridgeWitness",
        "system_peers",
        "da_submitCiphertexts",
        "da_submitProofs",
        "hegemon_developmentPendingActionChunk",
        "a_method_that_does_not_exist",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(!public_methods.contains(method), "catalog exposes {method}");
        let response = public.post(call(id as u64, method, json!([]))).await;
        assert!(
            response.get("error").is_some(),
            "dispatch exposed {method}: {response}"
        );
    }
    assert_eq!(snapshot_db(&public.node), before);
    assert!(public.node.state.read().pending_actions.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_existing_policies_and_auto_default_keep_their_surface() {
    for policy in ["auto", "", "safe", "pool", "unsafe"] {
        let rpc = HttpRpc::open(policy, high_limits(), None).await;
        let methods = rpc.catalog().await;
        assert!(methods.contains("rpc_methods"), "{policy}");
        assert_eq!(methods.contains("hegemon_submitAction"), policy == "unsafe");
        assert_eq!(
            methods.contains("hegemon_poolWork"),
            matches!(policy, "pool" | "unsafe")
        );
        let response = rpc.post(call(2, "hegemon_submitAction", json!([{}]))).await;
        if policy == "unsafe" {
            assert_eq!(response["result"]["success"], false);
        } else {
            assert!(response.get("error").is_some(), "{policy}: {response}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_batch_charges_each_submission_and_forwarded_headers_do_not_reset_it() {
    let rpc = HttpRpc::open("public-submit", Default::default(), None).await;
    let before = snapshot_db(&rpc.node);
    let payload = (0..8)
        .map(|id| call(id, "hegemon_submitAction", json!([{}])))
        .collect::<Vec<_>>();
    let rows = rpc.post(json!(payload)).await;
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 8);
    for response in &rows[..6] {
        assert_ne!(
            response["error"]["code"],
            json!(-32070),
            "charged too early: {response}"
        );
    }
    for response in &rows[6..] {
        assert_eq!(
            response["error"]["code"], -32070,
            "missing batch charge: {response}"
        );
    }
    for address in ["198.51.100.1", "203.0.113.2", "127.0.0.2", "::1"] {
        let response: Value = rpc
            .client
            .post(rpc.url())
            .header("x-forwarded-for", address)
            .header("x-real-ip", address)
            .header("forwarded", format!("for={address}"))
            .json(&call(9, "hegemon_submitAction", json!([{}])))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            response["error"]["code"], -32070,
            "forged {address}: {response}"
        );
    }
    assert_eq!(rpc.node.public_rpc_admission.snapshot().clients, 1);
    assert_eq!(snapshot_db(&rpc.node), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_full_client_table_denies_new_client_without_eviction() {
    let rpc = HttpRpc::open(
        "public-submit",
        public_admission::PublicRpcLimits {
            client_capacity: 1,
            ..high_limits()
        },
        None,
    )
    .await;
    // Populate the real bounded limiter, then submit over an actual socket from
    // a distinct transport IP. This controls table state without a forged header.
    rpc.node
        .public_rpc_admission
        .charge_submission("192.0.2.1".parse().unwrap())
        .unwrap();
    let response = rpc
        .client
        .post(rpc.url())
        .json(&call(1, "hegemon_submitAction", json!([{}])))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    let response: Value = response.json().await.unwrap();
    assert_eq!(response["error"]["code"], -32071, "{response}");
    assert_eq!(rpc.node.public_rpc_admission.snapshot().clients, 1);
    assert!(rpc.node.state.read().pending_actions.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_rejects_malformed_inactive_wrong_binding_and_other_action_families() {
    let rpc = HttpRpc::open("public-submit", high_limits(), None).await;
    let before = snapshot_db(&rpc.node);
    let mut candidates = vec![json!({}), private_spend_request()];
    for (field, value) in [
        ("family_id", 999),
        ("action_id", 0),
        ("action_id", 1),
        ("action_id", 2),
        ("action_id", 16),
        ("action_id", 17),
        ("binding_circuit", 65535),
        ("binding_crypto", 65535),
    ] {
        let mut candidate = private_spend_request();
        candidate[field] = json!(value);
        candidates.push(candidate);
    }
    let mut malformed = private_spend_request();
    malformed["public_args"] = json!("invalid base64 !");
    candidates.push(malformed);
    let mut unknown_field = private_spend_request();
    unknown_field["network"] = json!("wrong-network");
    candidates.push(unknown_field);
    for (id, candidate) in candidates.into_iter().enumerate() {
        let response = rpc
            .post(call(id as u64, "hegemon_submitAction", json!([candidate])))
            .await;
        assert!(
            response.get("error").is_some() || response["result"]["success"] == false,
            "{response}"
        );
    }
    let response = rpc
        .client
        .post(rpc.url())
        .header("content-type", "application/json")
        .body(vec![b' '; MAX_NATIVE_RPC_BODY_BYTES + 1])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(snapshot_db(&rpc.node), before);
    assert!(rpc.node.state.read().pending_actions.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_cors_is_closed_by_default_and_explicit_origin_is_exact() {
    for origin in [None, Some("https://wallet.example")] {
        let rpc = HttpRpc::open("public-submit", high_limits(), origin).await;
        for supplied in ["https://wallet.example", "https://attacker.example"] {
            let response = rpc
                .client
                .post(rpc.url())
                .header("origin", supplied)
                .json(&call(1, "system_health", json!([])))
                .send()
                .await
                .unwrap();
            let allowed = response
                .headers()
                .get("access-control-allow-origin")
                .map(|v| v.to_str().unwrap());
            assert_eq!(allowed, origin);
            let preflight = rpc
                .client
                .request(reqwest::Method::OPTIONS, rpc.url())
                .header("origin", supplied)
                .header("access-control-request-method", "POST")
                .send()
                .await
                .unwrap();
            assert_eq!(preflight.status(), reqwest::StatusCode::NO_CONTENT);
            let allowed = preflight
                .headers()
                .get("access-control-allow-origin")
                .map(|v| v.to_str().unwrap());
            assert_eq!(allowed, origin);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_disconnected_safe_read_workers_keep_bounded_reservations_until_completion() {
    let rpc = HttpRpc::open(
        "public-submit",
        public_admission::PublicRpcLimits {
            request_concurrency: 2,
            ..high_limits()
        },
        None,
    )
    .await;
    let state = rpc.node.state.write();
    let first = rpc.raw_post(call(1, "chain_getHeader", json!([]))).await;
    let second = rpc.raw_post(call(2, "chain_getHeader", json!([]))).await;
    wait_counts(&rpc.node, 2, 0).await;
    drop(first);
    drop(second);
    let response = rpc
        .client
        .post(rpc.url())
        .json(&call(3, "rpc_methods", json!([])))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        rpc.node.public_rpc_admission.snapshot().requests_in_flight,
        2
    );
    for path in ["/", "/health"] {
        let response = rpc
            .client
            .get(format!("http://{}{path}", rpc.addr))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            "GET {path} must share public capacity"
        );
    }
    drop(state);
    wait_counts(&rpc.node, 0, 0).await;
    assert!(rpc
        .post(call(4, "chain_getHeader", json!([])))
        .await
        .get("result")
        .is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_disconnected_submit_keeps_public_permit_and_local_capacity_available() {
    let rpc = HttpRpc::open("public-submit", high_limits(), None).await;
    let before = snapshot_db(&rpc.node);
    let state = rpc.node.state.write();
    let socket = rpc
        .raw_post(call(
            1,
            "hegemon_submitAction",
            json!([private_spend_request()]),
        ))
        .await;
    wait_counts(&rpc.node, 1, 1).await;
    drop(socket);
    let local = Arc::clone(&rpc.node.local_pending_proof_admission_semaphore)
        .try_acquire_owned()
        .expect("reserved local lane remains available");
    let shared = Arc::clone(&rpc.node.pending_proof_admission_semaphore)
        .try_acquire_owned()
        .expect("public work does not borrow existing shared verifier lane");
    let response = rpc
        .post(call(
            2,
            "hegemon_submitAction",
            json!([private_spend_request()]),
        ))
        .await;
    assert_eq!(response["error"]["code"], -32073, "{response}");
    assert_eq!(
        rpc.node
            .public_rpc_admission
            .snapshot()
            .submissions_in_flight,
        1
    );
    drop(local);
    drop(shared);
    drop(state);
    wait_counts(&rpc.node, 0, 0).await;
    // The disconnected worker finishes through unchanged legacy source denial.
    assert_eq!(snapshot_db(&rpc.node), before);
    assert!(rpc.node.state.read().pending_actions.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_parser_and_batch_failures_release_worker_capacity() {
    let rpc = HttpRpc::open("public-submit", high_limits(), None).await;
    let before = snapshot_db(&rpc.node);
    let malformed = rpc
        .client
        .post(rpc.url())
        .header("content-type", "application/json")
        .body("{ malformed")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), reqwest::StatusCode::BAD_REQUEST);
    wait_counts(&rpc.node, 0, 0).await;
    let empty = rpc.post(json!([])).await;
    assert_eq!(empty["error"]["code"], -32600);
    let large = rpc
        .post(json!((0..=MAX_NATIVE_RPC_BATCH_REQUESTS)
            .map(|id| call(id as u64, "system_health", json!([])))
            .collect::<Vec<_>>()))
        .await;
    assert_eq!(large["error"]["code"], -32600);
    wait_counts(&rpc.node, 0, 0).await;
    assert_eq!(rpc.node.public_rpc_admission.snapshot().clients, 1);
    assert_eq!(snapshot_db(&rpc.node), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_safe_reads_are_rate_charged_per_batch_item() {
    let rpc = HttpRpc::open(
        "public-submit",
        public_admission::PublicRpcLimits {
            requests_per_minute: 2,
            ..high_limits()
        },
        None,
    )
    .await;
    let rows = rpc
        .post(json!([
            call(1, "chain_getHeader", json!([])),
            call(2, "system_health", json!([])),
            call(3, "rpc_methods", json!([]))
        ]))
        .await;
    assert!(rows[0].get("result").is_some());
    assert!(rows[1].get("result").is_some());
    assert_eq!(rows[2]["error"]["code"], -32075);
    assert_eq!(rpc.node.public_rpc_admission.snapshot().clients, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_rejects_oversized_id_without_echoing_it() {
    let rpc = HttpRpc::open("public-submit", high_limits(), None).await;
    let payload = json!({
        "jsonrpc": "2.0", "id": "x".repeat(MAX_NATIVE_RPC_BODY_BYTES - 1024),
        "method": "system_name", "params": []
    });
    assert!(serde_json::to_vec(&payload).unwrap().len() < MAX_NATIVE_RPC_BODY_BYTES);
    let response = rpc
        .client
        .post(rpc.url())
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let bytes = response.bytes().await.unwrap();
    assert!(
        bytes.len() < 1024,
        "bounded error must not re-echo caller id"
    );
    let result: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["error"]["code"], -32600);
    assert_eq!(result["id"], Value::Null);
    wait_counts(&rpc.node, 0, 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_rejects_noncanonical_request_envelopes_before_action_dispatch() {
    let rpc = HttpRpc::open("public-submit", high_limits(), None).await;
    let before = snapshot_db(&rpc.node);
    let mut missing_version = call(1, "hegemon_submitAction", json!([private_spend_request()]));
    missing_version.as_object_mut().unwrap().remove("jsonrpc");
    let mut wrong_version = call(2, "hegemon_submitAction", json!([private_spend_request()]));
    wrong_version["jsonrpc"] = json!("1.0");
    let mut nonstring_method = call(3, "hegemon_submitAction", json!([private_spend_request()]));
    nonstring_method["method"] = json!(42);
    let mut boolean_id = call(4, "hegemon_submitAction", json!([private_spend_request()]));
    boolean_id["id"] = json!(true);
    for request in [
        missing_version,
        wrong_version,
        nonstring_method,
        boolean_id,
        call(
            5,
            "hegemon_submitAction",
            json!("not a parameter container"),
        ),
    ] {
        let response = rpc.post(request).await;
        assert_eq!(response["error"]["code"], -32600, "{response}");
    }
    assert_eq!(snapshot_db(&rpc.node), before);
    assert!(rpc.node.state.read().pending_actions.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_disconnect_during_body_collection_releases_unstarted_request() {
    let rpc = HttpRpc::open(
        "public-submit",
        public_admission::PublicRpcLimits {
            request_concurrency: 1,
            ..high_limits()
        },
        None,
    )
    .await;
    let mut socket = tokio::net::TcpStream::connect(rpc.addr).await.unwrap();
    socket.write_all(format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{{",
        rpc.addr
    ).as_bytes()).await.unwrap();
    socket.flush().await.unwrap();
    wait_counts(&rpc.node, 1, 0).await;
    drop(socket);
    wait_counts(&rpc.node, 0, 0).await;
    assert_eq!(rpc.node.public_rpc_admission.snapshot().clients, 1);
    assert!(rpc
        .post(call(1, "system_health", json!([])))
        .await
        .get("result")
        .is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_malformed_bodies_cannot_bypass_preparse_rate_accounting() {
    let rpc = HttpRpc::open(
        "public-submit",
        public_admission::PublicRpcLimits {
            requests_per_minute: 2,
            ..high_limits()
        },
        None,
    )
    .await;
    let before = snapshot_db(&rpc.node);
    for _ in 0..2 {
        let response = rpc
            .client
            .post(rpc.url())
            .header("content-type", "application/json")
            .body("{ malformed")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        let _ = response.bytes().await.unwrap();
        wait_counts(&rpc.node, 0, 0).await;
    }
    let response = rpc
        .client
        .post(rpc.url())
        .header("content-type", "application/json")
        .body("{ malformed again")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    let denial: Value = response.json().await.unwrap();
    assert_eq!(denial["error"]["code"], -32075);
    assert_eq!(denial["id"], Value::Null);
    let valid = rpc
        .client
        .post(rpc.url())
        .json(&call(1, "system_health", json!([])))
        .send()
        .await
        .unwrap();
    assert_eq!(valid.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    let denial: Value = valid.json().await.unwrap();
    assert_eq!(denial["error"]["code"], -32075);
    wait_counts(&rpc.node, 0, 0).await;
    assert_eq!(rpc.node.public_rpc_admission.snapshot().clients, 1);
    assert_eq!(snapshot_db(&rpc.node), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_http_single_requests_are_charged_exactly_once() {
    let rpc = HttpRpc::open(
        "public-submit",
        public_admission::PublicRpcLimits {
            requests_per_minute: 2,
            ..high_limits()
        },
        None,
    )
    .await;
    for id in 0..2 {
        let response = rpc.post(call(id, "system_name", json!([]))).await;
        assert!(response.get("result").is_some());
    }
    let response = rpc
        .client
        .post(rpc.url())
        .json(&call(3, "system_name", json!([])))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    let denial: Value = response.json().await.unwrap();
    assert_eq!(denial["error"]["code"], -32075);
    wait_counts(&rpc.node, 0, 0).await;
}
