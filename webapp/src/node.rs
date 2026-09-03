//! Talking to the Freenet node this page was served from.
//!
//! The gateway injects an auth token and serves the app under a CSP whose
//! `connect-src` is the gateway alone, so this WebSocket is the app's only
//! route to anything. Everything the page shows arrives through it.

use dioxus::prelude::*;
use freenet_stdlib::client_api::WebApi;
use futures::channel::mpsc;

pub static WEB_API: GlobalSignal<Option<WebApi>> = GlobalSignal::new(|| None);
pub static CONNECTION: GlobalSignal<Connection> = GlobalSignal::new(|| Connection::Connecting);

#[derive(Clone, PartialEq, Debug)]
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
pub async fn connect(
) -> Result<mpsc::UnboundedReceiver<Result<freenet_stdlib::client_api::HostResponse, String>>, String>
{
    use freenet_stdlib::client_api::{ClientError, HostResponse};
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
            let mapped = res.map_err(|e| e.to_string());
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
pub async fn connect(
) -> Result<mpsc::UnboundedReceiver<Result<freenet_stdlib::client_api::HostResponse, String>>, String>
{
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
