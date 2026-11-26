//! DB + HTTP integration tests for `bp-ent-relay`:
//! - Cross-tenant isolation across `/v1/vms/*`
//! - Same-tenant VM assignment boundary (`assigned_user_id` vs `VmManage`)
//! - Postgres `<= 24h` device cert `CHECK` enforcement
//! - Billing integrity across start -> stop -> start -> stop (stopped time never billed)
//! - CSR one-time enrollment token + single-use replay rejection + mTLS CSR renewal
//! - Stopped VM self-resurrection blocked (`403`)

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use bp_ent_core::testkit::TestDb;
use bp_ent_core::{AuthKind, Role};
use bp_ent_relay::{
    migrator, router_with_state, BoatCa, InMemoryUsageMeterSink, LocalMockProvisioner,
    RelayConfig, RelayState,
};
use rcgen::{CertificateParams, KeyPair};
use sqlx::Row;
use std::sync::Arc;
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

fn test_state(db: &TestDb) -> (RelayState, Arc<InMemoryUsageMeterSink>, Arc<BoatCa>) {
    let ca = Arc::new(BoatCa::generate_ephemeral("Test Boat CA").unwrap());
    let sink = Arc::new(InMemoryUsageMeterSink::default());
    let mut state = RelayState::with_ca(db.app_ctx(), ca.clone());
    state.provisioner = Arc::new(LocalMockProvisioner::default());
    state.meter_sink = sink.clone();
    state.config = RelayConfig::default();
    (state, sink, ca)
}

#[tokio::test]
async fn boat_vms_enforce_tenant_isolation_billing_and_csr_lifecycle() {
    let Some(tdb) = TestDb::new([migrator()]).await else {
        return;
    };

    let tenant_a = tdb.tenant("acme-hw").await;
    let tenant_b = tdb.tenant("rival-hw").await;

    let admin_a = tdb.user(tenant_a, Role::OrgAdmin).await;
    let eng_a1 = tdb.user(tenant_a, Role::Engineer).await;
    let eng_a2 = tdb.user(tenant_a, Role::Engineer).await;
    let admin_b = tdb.user(tenant_b, Role::OrgAdmin).await;

    let tok_admin_a = tdb.token(&admin_a, AuthKind::UserToken).await;
    let tok_eng_a1 = tdb.token(&eng_a1, AuthKind::UserToken).await;
    let tok_eng_a2 = tdb.token(&eng_a2, AuthKind::UserToken).await;
    let tok_admin_b = tdb.token(&admin_b, AuthKind::UserToken).await;

    let (state, sink, _ca) = test_state(&tdb);
    let app = router_with_state(state);

    // 1. Admin A creates a Boat VM assigned to Engineer A1.
    let create_req = Request::builder()
        .method(Method::POST)
        .uri("/v1/vms")
        .header(header::AUTHORIZATION, format!("Bearer {tok_admin_a}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": "boat-eng1",
                "assignedUserId": eng_a1.user_id.0,
                "region": "us-east-1"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(create_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let vm_id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();

    // 2. Tenant B admin gets 404 (not 403) when accessing Tenant A's VM.
    for (method, path) in [
        (Method::GET, format!("/v1/vms/{vm_id}")),
        (Method::POST, format!("/v1/vms/{vm_id}/wake")),
        (Method::POST, format!("/v1/vms/{vm_id}/stop")),
        (Method::POST, format!("/v1/vms/{vm_id}/cert")),
        (Method::POST, format!("/v1/vms/{vm_id}/enroll")),
        (Method::DELETE, format!("/v1/vms/{vm_id}")),
    ] {
        let req = Request::builder()
            .method(method)
            .uri(&path)
            .header(header::AUTHORIZATION, format!("Bearer {tok_admin_b}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let r = app.clone().oneshot(req).await.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "tenant B leaked on {path}");
    }

    // 3. Engineer A2 (same tenant, not assigned) also gets 404; Engineer A1 succeeds.
    let r_a2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/v1/vms/{vm_id}"))
                .header(header::AUTHORIZATION, format!("Bearer {tok_eng_a2}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_a2.status(), StatusCode::NOT_FOUND);

    // 4. Enrollment token -> CSR enroll -> single-use replay rejection.
    let r_enroll_tok = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/vms/{vm_id}/enroll"))
                .header(header::AUTHORIZATION, format!("Bearer {tok_admin_a}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_enroll_tok.status(), StatusCode::OK);
    let enroll_json: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(r_enroll_tok.into_body(), 65536).await.unwrap())
            .unwrap();
    let enroll_token = enroll_json["enrollmentToken"].as_str().unwrap().to_string();

    let vm_key = KeyPair::generate().unwrap();
    let csr_pem = CertificateParams::default()
        .serialize_request(&vm_key)
        .unwrap()
        .pem()
        .unwrap();

    let r_enroll = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/relay/boat/enroll")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "enrollmentToken": enroll_token,
                        "csrPem": csr_pem,
                        "ttlSecs": 3600
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_enroll.status(), StatusCode::OK);
    let enrolled: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(r_enroll.into_body(), 65536).await.unwrap())
            .unwrap();
    let serial_hex = enrolled["serialHex"].as_str().unwrap().to_string();

    // Replay of the same enrollment token MUST fail.
    let r_replay = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/relay/boat/enroll")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "enrollmentToken": enroll_token,
                        "csrPem": csr_pem,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_replay.status(), StatusCode::UNAUTHORIZED);

    // 5. Stopped VM cannot self-renew or connect (403 Forbidden).
    let mut cert_cur = std::io::Cursor::new(enrolled["certPem"].as_str().unwrap().as_bytes());
    let cert_der = rustls_pemfile::certs(&mut cert_cur).next().unwrap().unwrap();
    let verified_id = bp_ent_relay::ca::verify_client_cert_der(&cert_der, OffsetDateTime::now_utc()).unwrap();
    assert_eq!(verified_id.serial_hex, serial_hex);

    let mut req_stopped_renew = Request::builder()
        .method(Method::POST)
        .uri("/v1/relay/boat/renew")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "csrPem": csr_pem, "ttlSecs": 3600 }).to_string(),
        ))
        .unwrap();
    req_stopped_renew.extensions_mut().insert(verified_id.clone());
    let r_stopped_renew = app.clone().oneshot(req_stopped_renew).await.unwrap();
    assert_eq!(r_stopped_renew.status(), StatusCode::FORBIDDEN);

    // 6. Start -> Stop -> Start -> Stop billing integrity check:
    // Simulate first start 2 hours ago, stop now -> ~7200s, then wait/backdate second start 5m ago,
    // stop now -> ~300s (NOT 7500s!).
    let r_a1_wake = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/vms/{vm_id}/wake"))
                .header(header::AUTHORIZATION, format!("Bearer {tok_eng_a1}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_a1_wake.status(), StatusCode::OK);

    // Now that VM is running, mTLS CSR renewal succeeds.
    let mut req_renew = Request::builder()
        .method(Method::POST)
        .uri("/v1/relay/boat/renew")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "csrPem": csr_pem, "ttlSecs": 3600 }).to_string(),
        ))
        .unwrap();
    req_renew.extensions_mut().insert(verified_id);
    let r_renew = app.clone().oneshot(req_renew).await.unwrap();
    assert_eq!(r_renew.status(), StatusCode::OK);

    // Backdate first started_at by 2 hours using admin pool.
    sqlx::query("UPDATE boat_vms SET started_at = now() - interval '2 hours' WHERE id = $1")
        .bind(vm_id)
        .execute(tdb.admin_pool())
        .await
        .unwrap();

    let r_stop1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/vms/{vm_id}/stop"))
                .header(header::AUTHORIZATION, format!("Bearer {tok_eng_a1}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_stop1.status(), StatusCode::OK);

    // Verify started_at is NULL after stop!
    let started_after_stop: Option<OffsetDateTime> = sqlx::query("SELECT started_at FROM boat_vms WHERE id = $1")
        .bind(vm_id)
        .fetch_one(tdb.admin_pool())
        .await
        .unwrap()
        .get("started_at");
    assert!(started_after_stop.is_none(), "started_at must be NULL when stopped");

    // Second wake & stop.
    let r_wake2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/vms/{vm_id}/wake"))
                .header(header::AUTHORIZATION, format!("Bearer {tok_eng_a1}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_wake2.status(), StatusCode::OK);

    let r_stop2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/vms/{vm_id}/stop"))
                .header(header::AUTHORIZATION, format!("Bearer {tok_eng_a1}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_stop2.status(), StatusCode::OK);

    let records = sink.records.lock().await;
    assert_eq!(records.len(), 2);
    assert!(records[0].duration_seconds >= 7190);
    assert!(records[1].duration_seconds < 60, "second interval must not bill stopped time: {}", records[1].duration_seconds);

    // 7. Reject >24h cert TTL.
    let r_cert_bad = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/vms/{vm_id}/cert"))
                .header(header::AUTHORIZATION, format!("Bearer {tok_admin_a}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"ttlSecs": 90000}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_cert_bad.status(), StatusCode::UNPROCESSABLE_ENTITY);

    drop(records);
    tdb.cleanup().await;
}

#[tokio::test]
async fn bidirectional_relay_bridge_forwards_allowlisted_paths_and_blocks_ssrf() {
    use bp_ent_relay::{bridge, MtlsRelayServer};
    use tokio::net::TcpListener;

    let Some(tdb) = TestDb::new([migrator()]).await else {
        return;
    };

    let tenant = tdb.tenant("bridge-org").await;
    let admin = tdb.user(tenant, Role::OrgAdmin).await;
    let tok_admin = tdb.token(&admin, AuthKind::UserToken).await;

    let (state, _sink, ca) = test_state(&tdb);
    let app = router_with_state(state.clone());

    // Start client HTTP listener + mTLS listener.
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let app_srv = app.clone();
    let client_task = tokio::spawn(async move {
        let _ = axum::serve(client_listener, app_srv).await;
    });

    let mtls_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mtls_addr = mtls_listener.local_addr().unwrap();
    let mtls_server = MtlsRelayServer::new(&ca, &["localhost"], app.clone()).unwrap();
    let mtls_task = tokio::spawn(async move {
        let _ = mtls_server.serve(mtls_listener).await;
    });

    // Create & wake VM, issue device cert files into temp dir.
    let created_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/vms")
                .header(header::AUTHORIZATION, format!("Bearer {tok_admin}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"name":"bridge-boat"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created_resp.status(), StatusCode::OK);
    let created: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(created_resp.into_body(), 65536).await.unwrap(),
    )
    .unwrap();
    let vm_id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();

    let wake_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/vms/{vm_id}/wake"))
                .header(header::AUTHORIZATION, format!("Bearer {tok_admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wake_resp.status(), StatusCode::OK);

    let cert_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/vms/{vm_id}/cert"))
                .header(header::AUTHORIZATION, format!("Bearer {tok_admin}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cert_resp.status(), StatusCode::OK);
    let cert_json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(cert_resp.into_body(), 65536).await.unwrap(),
    )
    .unwrap();

    let tmp_dir = std::env::temp_dir().join(format!("bp-bridge-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let ca_path = tmp_dir.join("ca.pem");
    let crt_path = tmp_dir.join("device.crt");
    let key_path = tmp_dir.join("device.key");
    let tok_path = tmp_dir.join("user.token");
    std::fs::write(&ca_path, cert_json["caCertPem"].as_str().unwrap()).unwrap();
    std::fs::write(&crt_path, cert_json["certPem"].as_str().unwrap()).unwrap();
    std::fs::write(&key_path, cert_json["keyPem"].as_str().unwrap()).unwrap();
    std::fs::write(&tok_path, &tok_admin).unwrap();

    // Two mock local hubs (Boat & Desktop).
    let boat_hub_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let boat_hub_addr = boat_hub_l.local_addr().unwrap();
    let boat_hub_app = axum::Router::new()
        .route(
            "/hello",
            axum::routing::get(|| async { axum::Json(serde_json::json!({ "ok": true })) }),
        )
        .route(
            "/far/rpc",
            axum::routing::post(|headers: axum::http::HeaderMap, body: String| async move {
                let peer = headers
                    .get("x-backplane-peer")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let had_auth = headers.contains_key(axum::http::header::AUTHORIZATION);
                axum::Json(serde_json::json!({ "from": "boat", "peer": peer, "hadAuth": had_auth, "echo": body }))
            }),
        );
    let boat_hub_task = tokio::spawn(async move {
        let _ = axum::serve(boat_hub_l, boat_hub_app).await;
    });

    let desk_hub_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let desk_hub_addr = desk_hub_l.local_addr().unwrap();
    let desk_hub_app = axum::Router::new().route(
        "/far/rpc",
        axum::routing::post(|body: String| async move {
            axum::Json(serde_json::json!({ "from": "desktop", "echo": body }))
        }),
    );
    let desk_hub_task = tokio::spawn(async move {
        let _ = axum::serve(desk_hub_l, desk_hub_app).await;
    });

    // Reserve peer listener ports by picking free ports via TcpListener then dropping, or spawning bridge directly.
    let boat_peer_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let boat_peer_addr = boat_peer_l.local_addr().unwrap();
    drop(boat_peer_l);
    let desk_peer_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let desk_peer_addr = desk_peer_l.local_addr().unwrap();
    drop(desk_peer_l);

    let boat_agent_task = tokio::spawn({
        let ca_path = ca_path.clone();
        let crt_path = crt_path.clone();
        let key_path = key_path.clone();
        async move {
            let _ = bridge::run_boat_agent(
                format!("wss://localhost:{}/v1/relay/boat/connect", mtls_addr.port()),
                ca_path,
                crt_path,
                key_path,
                format!("http://{boat_hub_addr}"),
                boat_peer_addr,
            )
            .await;
        }
    });

    let desk_bridge_task = tokio::spawn(async move {
        let _ = bridge::run_desktop_bridge(
            format!("http://127.0.0.1:{}", client_addr.port()),
            vm_id,
            tok_path,
            None,
            format!("http://{desk_hub_addr}"),
            desk_peer_addr,
        )
        .await;
    });

    let http = reqwest::Client::new();
    // Wait until end-to-end Desktop -> Boat works.
    let mut reached_boat = false;
    for _ in 0..40 {
        if let Ok(r) = http
            .post(format!("http://{desk_peer_addr}/far/rpc"))
            .header("x-backplane-peer", "p_desk")
            .header("authorization", "Bearer must-not-forward")
            .body(r#"{"m":"ping"}"#)
            .send()
            .await
        {
            if r.status() == 200 {
                let v: serde_json::Value = r.json().await.unwrap();
                assert_eq!(v["from"], "boat");
                assert_eq!(v["peer"], "p_desk");
                assert_eq!(v["hadAuth"], false, "Authorization header must be stripped");
                reached_boat = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(reached_boat, "desktop-bridge did not reach boat local hub");

    // GET /hello works over relay (used by hub peer discovery).
    let r_hello = http
        .get(format!("http://{desk_peer_addr}/hello"))
        .send()
        .await
        .unwrap();
    assert_eq!(r_hello.status(), 200);

    // Reverse direction: Boat -> Desktop works.
    let r_desk = http
        .post(format!("http://{boat_peer_addr}/far/rpc"))
        .body(r#"{"m":"launch"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(r_desk.status(), 200);
    let v_desk: serde_json::Value = r_desk.json().await.unwrap();
    assert_eq!(v_desk["from"], "desktop");

    // Non-allowlisted paths and query strings MUST be rejected with 403 Forbidden.
    let r_ssrf = http
        .get(format!("http://{desk_peer_addr}/v1/admin/users"))
        .send()
        .await
        .unwrap();
    assert_eq!(r_ssrf.status(), 403);
    let r_qs = http
        .post(format!("http://{desk_peer_addr}/far/rpc?extra=1"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r_qs.status(), 403);

    boat_agent_task.abort();
    desk_bridge_task.abort();
    boat_hub_task.abort();
    desk_hub_task.abort();
    mtls_task.abort();
    client_task.abort();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    tdb.cleanup().await;
}

#[tokio::test]
async fn relay_enforces_per_user_isolation_surface_separation_and_far_ws_bridging() {
    use bp_ent_relay::{
        bridge, client_router_with_state, mtls_router_with_state, MtlsRelayServer,
    };
    use futures::{SinkExt, StreamExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};

    async fn connect_plain_ws(
        addr: std::net::SocketAddr,
        req: tokio_tungstenite::tungstenite::handshake::client::Request,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<TcpStream>,
        Box<tokio_tungstenite::tungstenite::Error>,
    > {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (ws, _) = tokio_tungstenite::client_async(req, tcp)
            .await
            .map_err(Box::new)?;
        Ok(ws)
    }

    let Some(tdb) = TestDb::new([migrator()]).await else {
        return;
    };

    let tenant_a = tdb.tenant("iso-org-a").await;
    let tenant_b = tdb.tenant("iso-org-b").await;

    let admin_a = tdb.user(tenant_a, Role::OrgAdmin).await;
    let eng_a1 = tdb.user(tenant_a, Role::Engineer).await;
    let eng_a2 = tdb.user(tenant_a, Role::Engineer).await;
    let admin_b = tdb.user(tenant_b, Role::OrgAdmin).await;

    let tok_admin_a = tdb.token(&admin_a, AuthKind::UserToken).await;
    let tok_eng_a1 = tdb.token(&eng_a1, AuthKind::UserToken).await;
    let tok_eng_a2 = tdb.token(&eng_a2, AuthKind::UserToken).await;
    let tok_admin_b = tdb.token(&admin_b, AuthKind::UserToken).await;
    let tok_device_a1 = tdb.token(&eng_a1, AuthKind::DeviceToken).await;

    let (state, _sink, ca) = test_state(&tdb);
    let client_app = client_router_with_state(state.clone());
    let mtls_app = mtls_router_with_state(state.clone());

    // 1. Verify route surface separation: client router has no mTLS connect, mTLS router has no /v1/vms.
    let r_no_mtls_on_client = client_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/relay/boat/connect")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_no_mtls_on_client.status(), StatusCode::NOT_FOUND);

    let r_no_vms_on_mtls = mtls_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/vms")
                .header(header::AUTHORIZATION, format!("Bearer {tok_admin_a}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r_no_vms_on_mtls.status(), StatusCode::NOT_FOUND);

    // 2. Create & wake VM assigned strictly to eng_a1.
    let created_resp = client_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/vms")
                .header(header::AUTHORIZATION, format!("Bearer {tok_admin_a}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "name": "eng1-boat",
                        "assignedUserId": eng_a1.user_id.0
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(created_resp.status(), StatusCode::OK);
    let created: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(created_resp.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    let vm_id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();

    let cert_resp = client_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/vms/{vm_id}/cert"))
                .header(header::AUTHORIZATION, format!("Bearer {tok_admin_a}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cert_resp.status(), StatusCode::OK);
    let cert_json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(cert_resp.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();

    let wake_resp = client_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/vms/{vm_id}/wake"))
                .header(header::AUTHORIZATION, format!("Bearer {tok_eng_a1}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wake_resp.status(), StatusCode::OK);

    // 3. Start listeners so real WebSocket upgrades can be tested.
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client_srv = client_app.clone();
    let client_task = tokio::spawn(async move {
        let _ = axum::serve(client_listener, client_srv).await;
    });

    let mtls_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mtls_addr = mtls_listener.local_addr().unwrap();
    let mtls_server = MtlsRelayServer::new(&ca, &["localhost"], mtls_app.clone()).unwrap();
    let mtls_task = tokio::spawn(async move {
        let _ = mtls_server.serve(mtls_listener).await;
    });

    // Cross-tenant admin, same-tenant other engineer, same-tenant OrgAdmin, and DeviceToken MUST all be rejected!
    for (label, tok, expected) in [
        ("tenant_b_admin", tok_admin_b.as_str(), StatusCode::NOT_FOUND),
        ("same_tenant_eng_a2", tok_eng_a2.as_str(), StatusCode::NOT_FOUND),
        ("same_tenant_admin_a", tok_admin_a.as_str(), StatusCode::NOT_FOUND),
        ("device_token", tok_device_a1.as_str(), StatusCode::FORBIDDEN),
    ] {
        let mut req = format!("ws://127.0.0.1:{}/v1/relay/desktop/connect/{vm_id}", client_addr.port())
            .into_client_request()
            .unwrap();
        req.headers_mut().insert(
            header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Bearer {tok}")).unwrap(),
        );
        let err = connect_plain_ws(client_addr, req).await.unwrap_err();
        match *err {
            tokio_tungstenite::tungstenite::Error::Http(resp) => {
                assert_eq!(resp.status(), expected, "{label} got {}", resp.status());
            }
            other => panic!("{label} unexpected error: {other:?}"),
        }
    }

    // 4. Assigned owner connects desktop-bridge and Boat connects via mTLS; test /far/ws binary bridging.
    let tmp_dir = std::env::temp_dir().join(format!("bp-iso-test-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let ca_path = tmp_dir.join("ca.pem");
    let crt_path = tmp_dir.join("device.crt");
    let key_path = tmp_dir.join("device.key");
    let tok_path = tmp_dir.join("eng1.token");
    std::fs::write(&ca_path, cert_json["caCertPem"].as_str().unwrap()).unwrap();
    std::fs::write(&crt_path, cert_json["certPem"].as_str().unwrap()).unwrap();
    std::fs::write(&key_path, cert_json["keyPem"].as_str().unwrap()).unwrap();
    std::fs::write(&tok_path, &tok_eng_a1).unwrap();

    // Mock desktop hub supporting /far/ws upgrade and checking stripped Authorization + preserved HMAC headers.
    let desk_hub_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let desk_hub_addr = desk_hub_l.local_addr().unwrap();
    let desk_hub_app = axum::Router::new()
        .route(
            "/far/rpc",
            axum::routing::post(|| async { axum::Json(serde_json::json!({ "ok": true })) }),
        )
        .route(
            "/far/ws",
            axum::routing::get(
                |headers: axum::http::HeaderMap, ws: axum::extract::ws::WebSocketUpgrade| async move {
                    let peer = headers
                        .get("x-backplane-peer")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let ts = headers
                        .get("x-backplane-timestamp")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let sig = headers
                        .get("x-backplane-signature")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let had_auth = headers.contains_key(header::AUTHORIZATION);
                    ws.on_upgrade(move |mut sock| async move {
                        let meta = serde_json::json!({
                            "peer": peer,
                            "ts": ts,
                            "sig": sig,
                            "hadAuth": had_auth,
                        })
                        .to_string();
                        let _ = sock
                            .send(axum::extract::ws::Message::Binary(meta.into_bytes().into()))
                            .await;
                        while let Some(Ok(msg)) = sock.next().await {
                            match msg {
                                axum::extract::ws::Message::Binary(b) => {
                                    if sock
                                        .send(axum::extract::ws::Message::Binary(b))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                axum::extract::ws::Message::Close(_) => break,
                                _ => {}
                            }
                        }
                    })
                },
            ),
        );
    let desk_hub_task = tokio::spawn(async move {
        let _ = axum::serve(desk_hub_l, desk_hub_app).await;
    });

    let boat_hub_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let boat_hub_addr = boat_hub_l.local_addr().unwrap();
    let boat_hub_app = axum::Router::new().route(
        "/hello",
        axum::routing::get(|| async { axum::Json(serde_json::json!({ "ok": true })) }),
    );
    let boat_hub_task = tokio::spawn(async move {
        let _ = axum::serve(boat_hub_l, boat_hub_app).await;
    });

    let boat_peer_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let boat_peer_addr = boat_peer_l.local_addr().unwrap();
    drop(boat_peer_l);
    let desk_peer_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let desk_peer_addr = desk_peer_l.local_addr().unwrap();
    drop(desk_peer_l);

    let boat_agent_task = tokio::spawn(async move {
        let _ = bridge::run_boat_agent(
            format!("wss://localhost:{}/v1/relay/boat/connect", mtls_addr.port()),
            ca_path,
            crt_path,
            key_path,
            format!("http://{boat_hub_addr}"),
            boat_peer_addr,
        )
        .await;
    });

    let desk_bridge_task = tokio::spawn(async move {
        let _ = bridge::run_desktop_bridge(
            format!("http://127.0.0.1:{}", client_addr.port()),
            vm_id,
            tok_path,
            None,
            format!("http://{desk_hub_addr}"),
            desk_peer_addr,
        )
        .await;
    });

    let http = reqwest::Client::new();
    let mut ready = false;
    for _ in 0..40 {
        if let Ok(r) = http
            .post(format!("http://{boat_peer_addr}/far/rpc"))
            .body("{}")
            .send()
            .await
        {
            if r.status() == 200 {
                ready = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(ready, "eng_a1 desktop-bridge did not connect to boat");

    // End-to-end /far/ws upgrade from Boat -> Relay -> Desktop hub!
    let mut ws_req = format!("ws://{boat_peer_addr}/far/ws")
        .into_client_request()
        .unwrap();
    ws_req
        .headers_mut()
        .insert("X-Backplane-Peer", "p_boat".parse().unwrap());
    ws_req
        .headers_mut()
        .insert("X-Backplane-Timestamp", "1700000000".parse().unwrap());
    ws_req
        .headers_mut()
        .insert("X-Backplane-Signature", "sha256=deadbeef".parse().unwrap());
    ws_req.headers_mut().insert(
        header::AUTHORIZATION,
        "Bearer must-not-cross-tunnel".parse().unwrap(),
    );

    let mut ws_stream = connect_plain_ws(boat_peer_addr, ws_req).await.unwrap();
    let first = ws_stream.next().await.unwrap().unwrap();
    let meta: serde_json::Value = match first {
        Message::Binary(b) => serde_json::from_slice(&b).unwrap(),
        other => panic!("expected binary metadata frame, got {other:?}"),
    };
    assert_eq!(meta["peer"], "p_boat");
    assert_eq!(meta["ts"], "1700000000");
    assert_eq!(meta["sig"], "sha256=deadbeef");
    assert_eq!(meta["hadAuth"], false);

    // Binary echo round-trip over /far/ws.
    let sample = vec![0x01, 0x02, 0x03, 0xfe, 0xff];
    ws_stream
        .send(Message::Binary(sample.clone().into()))
        .await
        .unwrap();
    let echoed = ws_stream.next().await.unwrap().unwrap();
    assert_eq!(echoed, Message::Binary(sample.into()));
    let _ = ws_stream.close(None).await;

    // Non-/far/ws upgrade must be rejected 403.
    let bad_ws_req = format!("ws://{boat_peer_addr}/v1/admin")
        .into_client_request()
        .unwrap();
    let bad_err = connect_plain_ws(boat_peer_addr, bad_ws_req)
        .await
        .unwrap_err();
    match *bad_err {
        tokio_tungstenite::tungstenite::Error::Http(resp) => assert_eq!(resp.status(), 403),
        other => panic!("expected HTTP 403, got {other:?}"),
    }

    // Stop VM -> force disconnects desktop & boat sessions, closes boat_relay_sessions row, writes audit entries.
    let stop_resp = client_app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/vms/{vm_id}/stop"))
                .header(header::AUTHORIZATION, format!("Bearer {tok_eng_a1}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stop_resp.status(), StatusCode::OK);

    let mut open_sessions = 1i64;
    for _ in 0..30 {
        open_sessions = sqlx::query_scalar(
            "SELECT count(*) FROM boat_relay_sessions WHERE vm_id = $1 AND disconnected_at IS NULL",
        )
        .bind(vm_id)
        .fetch_one(tdb.admin_pool())
        .await
        .unwrap();
        if open_sessions == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(open_sessions, 0, "relay sessions must close cleanly without orphans");

    let audit_actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log WHERE tenant_id = $1 AND target = $2 ORDER BY seq ASC",
    )
    .bind(tenant_a.0)
    .bind(format!("vm:{vm_id}"))
    .fetch_all(tdb.admin_pool())
    .await
    .unwrap();
    assert!(audit_actions.iter().any(|a| a == "boat_vm.relay_connected"));
    assert!(audit_actions.iter().any(|a| a == "boat_vm.relay_disconnected"));

    boat_agent_task.abort();
    desk_bridge_task.abort();
    boat_hub_task.abort();
    desk_hub_task.abort();
    mtls_task.abort();
    client_task.abort();
    let _ = std::fs::remove_dir_all(&tmp_dir);
    tdb.cleanup().await;
}
