// A stub origin that answers from a table and records what it was asked for, so
// "never touched the network" and "kept at most N in flight" are asserted rather
// than assumed.
//
// Hand-rolled on tokio rather than taken from a mock-HTTP crate because two of
// the things that have to be proved here are outside what one offers: the PEAK
// number of concurrent connections, and an origin that PROMISES a multi-gigabyte
// body so a followed redirect is caught by the request count rather than by
// waiting for the transfer.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use vpndetection::{Client, ClientBuilder};

pub mod corpus;

/// A response the stub is prepared to give for one path.
#[derive(Clone, Default)]
pub struct Route {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
    /// Sent as `Content-Length` while the body stays empty, so a client that
    /// follows a redirect it should not is told the file is enormous without the
    /// test having to produce one.
    pub promised_length: Option<u64>,
}

impl Route {
    pub fn ok(body: impl Into<String>) -> Self {
        Self { status: 200, body: body.into(), ..Self::default() }
    }

    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self { status, body: body.into(), ..Self::default() }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn promising(mut self, bytes: u64) -> Self {
        self.promised_length = Some(bytes);
        self
    }
}

#[derive(Default)]
struct State {
    routes: HashMap<String, Route>,
    calls: Vec<String>,
    in_flight: usize,
    peak: usize,
}

pub struct Stub {
    pub base_url: String,
    state: Arc<Mutex<State>>,
    delay: Duration,
}

impl Stub {
    /// Binds an ephemeral port and starts serving. The accept loop is detached
    /// and dies with the test process.
    pub async fn start(routes: impl IntoIterator<Item = (String, Route)>) -> Arc<Self> {
        Self::start_with_delay(routes, Duration::ZERO).await
    }

    /// The delay is what makes concurrent requests overlap, so a peak-in-flight
    /// measurement has something to measure.
    pub async fn start_with_delay(
        routes: impl IntoIterator<Item = (String, Route)>,
        delay: Duration,
    ) -> Arc<Self> {
        let state = Arc::new(Mutex::new(State {
            routes: routes.into_iter().collect(),
            ..State::default()
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let stub = Arc::new(Self {
            base_url: format!("http://127.0.0.1:{port}"),
            state: state.clone(),
            delay,
        });
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let state = state.clone();
                tokio::spawn(async move {
                    let _ = serve(socket, state, delay).await;
                });
            }
        });
        stub
    }

    /// Successful lookups for a set of addresses, which is what most cases want.
    pub fn ok_routes(ips: &[&str]) -> Vec<(String, Route)> {
        ips.iter()
            .map(|ip| (format!("/{ip}"), Route::ok(format!(r#"{{"ip":"{ip}","is_vpn":false}}"#))))
            .collect()
    }

    /// Adds a route after binding, for a response whose body has to name the
    /// stub's own address.
    pub fn route(&self, path: impl Into<String>, route: Route) {
        self.state.lock().unwrap().routes.insert(path.into(), route);
    }

    pub fn client(&self) -> ClientBuilder {
        Client::builder().base_url(&self.base_url)
    }

    pub fn count(&self) -> usize {
        self.state.lock().unwrap().calls.len()
    }

    pub fn calls(&self) -> Vec<String> {
        self.state.lock().unwrap().calls.clone()
    }

    pub fn peak_in_flight(&self) -> usize {
        self.state.lock().unwrap().peak
    }
}

async fn serve(
    mut socket: TcpStream,
    state: Arc<Mutex<State>>,
    delay: Duration,
) -> std::io::Result<()> {
    let path = match read_request_path(&mut socket).await? {
        Some(path) => path,
        None => return Ok(()),
    };

    let route = {
        let mut state = state.lock().unwrap();
        state.calls.push(path.clone());
        state.in_flight += 1;
        state.peak = state.peak.max(state.in_flight);
        state.routes.get(&path).cloned()
    };
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }

    // An unrouted address gets what the real API gives one, so a test that
    // forgets a route fails as a bad request rather than as a hang.
    let route = route.unwrap_or_else(|| Route::json(400, r#"{"error":"not a valid IP address"}"#));
    let result = write_response(&mut socket, &route).await;
    state.lock().unwrap().in_flight -= 1;
    result
}

/// The request line's path, percent-decoded and with any query string dropped,
/// which is the key routes are held under.
async fn read_request_path(socket: &mut TcpStream) -> std::io::Result<Option<String>> {
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        if socket.read(&mut byte).await? == 0 {
            return Ok(None);
        }
        request.push(byte[0]);
    }
    let line = String::from_utf8_lossy(&request);
    let Some(target) = line.split_whitespace().nth(1) else {
        return Ok(None);
    };
    let path = target.split('?').next().unwrap_or(target);
    Ok(Some(percent_decode(path)))
}

async fn write_response(socket: &mut TcpStream, route: &Route) -> std::io::Result<()> {
    let length = route.promised_length.unwrap_or(route.body.len() as u64);
    let mut head = format!(
        "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n",
        route.status
    );
    for (name, value) in &route.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    socket.write_all(head.as_bytes()).await?;
    socket.write_all(route.body.as_bytes()).await?;
    socket.flush().await?;
    // A promised body that is never written would leave the client waiting for
    // the rest of it, so the connection is closed instead: whoever followed the
    // redirect gets an error, and the request is on the record either way.
    socket.shutdown().await
}

fn percent_decode(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&path[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
