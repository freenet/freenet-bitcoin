//! Talking to the Freenet node this page was served from.
//!
//! The gateway injects an auth token and serves the app under a CSP whose
//! `connect-src` is the gateway alone, so this WebSocket is the app's only
//! route to anything. Everything the page shows arrives through it.

use dioxus::prelude::*;
use freenet_stdlib::client_api::{ClientError, WebApi};
use freenet_stdlib::prelude::ContractInstanceId;
use futures::channel::mpsc;

/// Everything that arrives from the node, including the failures.
///
/// The failures used to be flattened to a string and then ignored, which is
/// how a GET for a contract nobody publishes to became indistinguishable from
/// a contract with nothing in it. Resolving a generation pointer needs the
/// opposite: "the network says there is nothing at that address" and "we did
/// not hear back" lead to different conclusions, and conflating them is a
/// downgrade primitive.
#[allow(dead_code)] // Constructed only on the wasm path; matched on both.
pub enum Incoming {
    Response(freenet_stdlib::client_api::HostResponse),
    Failed(Failure),
}

/// A request the node refused or could not complete.
pub struct Failure {
    /// The contract it was about, when the error names one. Many do not: the
    /// node reports a missing contract as a bare operation error, which is
    /// why the app keeps exactly one pointer GET in flight at a time.
    pub key: Option<ContractInstanceId>,
    /// The network answered, positively, that there is no such state.
    ///
    /// Deliberately narrow, and narrow in the safe direction: anything
    /// unrecognised is "we learned nothing", because a false "nothing is
    /// there" would let a stalled request push this page onto a stale
    /// build-time generation, while a false "we learned nothing" costs a
    /// warning banner.
    pub not_found: bool,
    pub message: String,
}

#[allow(dead_code)] // Called only on the wasm path.
fn classify(e: &ClientError) -> Failure {
    use freenet_stdlib::client_api::{ContractError, ErrorKind, RequestError};
    let message = e.to_string();
    let key = match e.kind() {
        ErrorKind::RequestError(RequestError::ContractError(
            ContractError::Get { key, .. }
            | ContractError::Put { key, .. }
            | ContractError::Update { key, .. }
            | ContractError::Subscribe { key, .. },
        )) => Some(*key.id()),
        _ => None,
    };
    let lowered = message.to_ascii_lowercase();
    Failure {
        key,
        not_found: lowered.contains("not found") || lowered.contains("notfound"),
        message,
    }
}

// Only ever touched from wasm: the native build exists so `cargo test` and
// clippy can run the pure logic (address parsing, formatting, key derivation)
// without a browser, and it never opens a connection.
#[allow(dead_code)]
pub static WEB_API: GlobalSignal<Option<WebApi>> = GlobalSignal::new(|| None);
pub static CONNECTION: GlobalSignal<Connection> = GlobalSignal::new(|| Connection::Connecting);

#[derive(Clone, PartialEq, Debug)]
#[allow(dead_code)] // `Connected` is constructed only on the wasm path.
pub enum Connection {
    Connecting,
    Connected,
    Failed(String),
}

impl Connection {
    pub fn label(&self) -> &str {
        match self {
            Connection::Connecting => "connecting",
            Connection::Connected => "connected",
            Connection::Failed(_) => "no node",
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub async fn connect() -> Result<mpsc::UnboundedReceiver<Incoming>, String> {
    use freenet_stdlib::client_api::HostResponse;
    use wasm_bindgen_futures::spawn_local;

    *CONNECTION.write() = Connection::Connecting;

    let url = websocket_url();
    let ws = web_sys::WebSocket::new(&url).map_err(|e| format!("websocket: {e:?}"))?;

    let (tx, rx) = mpsc::unbounded();
    let (ready_tx, ready_rx) = futures::channel::oneshot::channel();
    let tx2 = tx.clone();

    let api = WebApi::start(
        ws,
        move |res: Result<HostResponse, ClientError>| {
            let mapped = match res {
                Ok(r) => Incoming::Response(r),
                Err(e) => Incoming::Failed(classify(&e)),
            };
            let tx = tx2.clone();
            spawn_local(async move {
                let _ = tx.unbounded_send(mapped);
            });
        },
        move |e| {
            dioxus::logger::tracing::warn!("websocket error: {e}");
        },
        move || {
            let _ = ready_tx.send(());
        },
    );

    ready_rx
        .await
        .map_err(|_| "connection dropped before ready".to_string())?;
    *WEB_API.write() = Some(api);
    *CONNECTION.write() = Connection::Connected;
    Ok(rx)
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn connect() -> Result<mpsc::UnboundedReceiver<Incoming>, String> {
    let (_tx, rx) = mpsc::unbounded();
    Ok(rx)
}

/// Derived from the page's own origin, never configured: the app talks to the
/// node that served it, whichever that is.
#[cfg(target_arch = "wasm32")]
fn websocket_url() -> String {
    let base = web_sys::window()
        .and_then(|w| {
            let loc = w.location();
            let proto = loc.protocol().ok()?;
            let host = loc.host().ok()?;
            let scheme = if proto == "https:" { "wss:" } else { "ws:" };
            Some(format!(
                "{scheme}//{host}/v1/contract/command?encodingProtocol=native"
            ))
        })
        .unwrap_or_else(|| {
            "ws://localhost:7509/v1/contract/command?encodingProtocol=native".to_string()
        });

    match auth_token() {
        Some(t) => format!("{base}&authToken={t}"),
        None => base,
    }
}

#[cfg(target_arch = "wasm32")]
fn auth_token() -> Option<String> {
    let w = web_sys::window()?;
    js_sys::Reflect::get(&w, &"__FREENET_AUTH_TOKEN__".into())
        .ok()?
        .as_string()
        .filter(|s| !s.is_empty())
}

/// GET a contract and subscribe, so later changes arrive as notifications.
#[cfg(target_arch = "wasm32")]
pub fn get_and_subscribe(id: freenet_stdlib::prelude::ContractInstanceId) {
    use freenet_stdlib::client_api::{ClientRequest, ContractRequest};

    let req = ContractRequest::Get {
        key: id,
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    };
    // The send future borrows the API, so it is driven to completion inside
    // the same borrow rather than escaping into a spawned task.
    wasm_bindgen_futures::spawn_local(async move {
        let mut guard = WEB_API.write();
        let Some(api) = guard.as_mut() else { return };
        if let Err(e) = api.send(ClientRequest::ContractOp(req)).await {
            dioxus::logger::tracing::warn!("get/subscribe failed: {e}");
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
pub fn get_and_subscribe(_id: freenet_stdlib::prelude::ContractInstanceId) {}

/// GET a generation pointer: no subscription, no contract code.
///
/// Separate from [`get_and_subscribe`] because a pointer is read once at
/// startup and a subscription to it would be a standing cost for a 100-byte
/// record that changes only when the bridge re-keys.
#[cfg(target_arch = "wasm32")]
pub fn get_pointer(id: ContractInstanceId) {
    use freenet_stdlib::client_api::{ClientRequest, ContractRequest};

    let req = ContractRequest::Get {
        key: id,
        return_contract_code: false,
        subscribe: false,
        blocking_subscribe: false,
    };
    wasm_bindgen_futures::spawn_local(async move {
        let mut guard = WEB_API.write();
        let Some(api) = guard.as_mut() else { return };
        if let Err(e) = api.send(ClientRequest::ContractOp(req)).await {
            dioxus::logger::tracing::warn!("pointer get failed: {e}");
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
pub fn get_pointer(_id: ContractInstanceId) {}

/// Run a task for the page's lifetime. A no-op off the browser, where the app
/// exists only so the pure logic can be tested.
#[cfg(target_arch = "wasm32")]
pub fn spawn(f: impl std::future::Future<Output = ()> + 'static) {
    wasm_bindgen_futures::spawn_local(f);
}

#[cfg(not(target_arch = "wasm32"))]
pub fn spawn(_f: impl std::future::Future<Output = ()> + 'static) {}

/// Wait, so a request that never comes back becomes a stated fact rather than
/// a page that waits forever.
#[cfg(target_arch = "wasm32")]
pub async fn sleep_ms(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        if let Some(w) = web_sys::window() {
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
        }
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep_ms(_ms: i32) {}
