// A recording reverse proxy, which is the only seam this SDK has.
//
// reqwest exposes no request hook and no per-request redirect policy, and the
// client is built inside the library, so the only way to see what was SENT is to
// be the origin it sends to. The recorder stands in front of staging: the base
// URL points at it, it forwards each request over HTTPS, and it hands back what
// came out. That is what makes "the key reached the wire" an observation rather
// than an inference, and it is what gives a test the raw answer the client
// itself does not keep.
//
// It also rewrites a redirect's `Location` back through itself, so the SECOND,
// unauthenticated request a download makes to object storage is on the record
// too. Without that, the assertion that matters most about a download - that the
// API key did NOT travel to a host with no business holding it - would be
// unobservable from outside the process.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A request under this prefix is the loop-back for a redirect the API answered
/// with; the rest of the path is the hex-encoded URL to fetch. Everything else
/// goes to the upstream API.
const VIA: &str = "/__via/";

/// Nothing larger is proxied at all. The download test budgets its transfer
/// against the size `metadata` publishes before it starts, so reaching this
/// means the suite is pointed somewhere unintended and must not carry on.
const MAX_BODY: usize = 32 << 20;

/// The most of an answer kept for a test to read afterwards. A dataset transfer
/// runs through this same code path, so a body is only ever remembered when it
/// is JSON and small.
const MAX_CAPTURED_BODY: usize = 1 << 20;

/// What a test is allowed to remember about a request that was made.
///
/// Only derived facts leave here. An assertion that fails prints its operands
/// and these logs are public, so whether the key was carried is a BOOLEAN and no
/// caller is ever handed the key itself.
#[derive(Clone, Debug)]
pub struct Fact {
    pub origin: String,
    pub path: String,
    pub carried_key: bool,
}

pub struct Recorder {
    /// What the client under test is pointed at.
    pub base_url: String,
    upstream: String,
    key: Option<String>,
    http: reqwest::Client,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    facts: Vec<Fact>,
    bodies: HashMap<String, String>,
}

impl Recorder {
    /// Binds an ephemeral port and starts serving. The accept loop is detached
    /// and dies with the runtime the test is running on.
    pub async fn start(upstream: &str, key: Option<String>) -> Arc<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("binding the recorder");
        let port = listener.local_addr().expect("the recorder's address").port();
        let recorder = Arc::new(Self {
            base_url: format!("http://127.0.0.1:{port}"),
            upstream: upstream.trim_end_matches('/').to_owned(),
            key,
            // Redirects are NOT followed here either: the download endpoint's
            // 302 has to reach the client under test, which is the thing being
            // measured.
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("building the forwarding client"),
            state: Mutex::new(State::default()),
        });

        let serving = recorder.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let recorder = serving.clone();
                tokio::spawn(async move {
                    let _ = recorder.serve(socket).await;
                });
            }
        });
        recorder
    }

    pub fn facts(&self) -> Vec<Fact> {
        self.state.lock().unwrap().facts.clone()
    }

    /// Whether the API key reached the wire on any request this recorder saw.
    pub fn carried_key(&self) -> bool {
        self.facts().iter().any(|fact| fact.carried_key)
    }

    /// A JSON answer this recorder captured, by the path it was served for.
    pub fn json_body(&self, path: &str) -> Option<serde_json::Value> {
        let raw = self.state.lock().unwrap().bodies.get(path).cloned()?;
        serde_json::from_str(&raw).ok()
    }

    async fn serve(&self, mut socket: TcpStream) -> std::io::Result<()> {
        let Some(request) = read_head(&mut socket).await? else {
            return Ok(());
        };
        let url = self.target(&request.target);
        self.note(&request, &url);
        let reply = self.forward(&request, &url).await;
        write_reply(&mut socket, &reply).await
    }

    fn target(&self, target: &str) -> String {
        match target.strip_prefix(VIA) {
            Some(encoded) => from_hex(encoded),
            None => format!("{}{target}", self.upstream),
        }
    }

    fn note(&self, request: &Request, url: &str) {
        let carried = self.key.as_deref().is_some_and(|key| {
            url.contains(key) || request.headers.iter().any(|(_, value)| value.contains(key))
        });
        let (origin, path) = split(url);
        self.state.lock().unwrap().facts.push(Fact { origin, path, carried_key: carried });
    }

    async fn forward(&self, request: &Request, url: &str) -> Reply {
        let mut outbound = self.http.get(url);
        for (name, value) in &request.headers {
            // Everything the client sent goes on, except what belongs to THIS
            // hop: a forwarded Host would override the one the URL implies, and
            // the framing headers describe a body this proxy is not relaying.
            if matches!(
                name.as_str(),
                "host" | "connection" | "content-length" | "transfer-encoding" | "accept-encoding"
            ) {
                continue;
            }
            outbound = outbound.header(name, value);
        }

        let mut response = match outbound.send().await {
            Ok(response) => response,
            Err(err) => return Reply::gateway(format!("forwarding to {url} failed: {err}")),
        };
        let status = response.status().as_u16();
        let mut headers = Vec::new();
        for name in ["content-type", "retry-after"] {
            if let Some(value) = response.headers().get(name).and_then(|v| v.to_str().ok()) {
                headers.push((name.to_owned(), value.to_owned()));
            }
        }
        // Pointed back at this recorder so the request that follows it is on the
        // record too. The presigned query string rides along inside the hex, so
        // the signature survives.
        if let Some(location) = response.headers().get("location").and_then(|v| v.to_str().ok()) {
            headers.push((
                "location".to_owned(),
                format!("{}{VIA}{}", self.base_url, to_hex(location)),
            ));
        }

        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len() + chunk.len() > MAX_BODY {
                        return Reply::gateway(format!(
                            "{url} answered more than {MAX_BODY} bytes"
                        ));
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(err) => return Reply::gateway(format!("reading {url} failed: {err}")),
            }
        }

        self.capture(url, &headers, &body);
        Reply { status, headers, body }
    }

    fn capture(&self, url: &str, headers: &[(String, String)], body: &[u8]) {
        let json = headers
            .iter()
            .any(|(name, value)| name == "content-type" && value.starts_with("application/json"));
        if !json || body.len() > MAX_CAPTURED_BODY {
            return;
        }
        let Ok(text) = std::str::from_utf8(body) else {
            return;
        };
        let (_, path) = split(url);
        self.state.lock().unwrap().bodies.insert(path, text.to_owned());
    }
}

struct Request {
    target: String,
    headers: Vec<(String, String)>,
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    /// A proxy failure the client can read. It arrives as a 502, which the SDK
    /// classifies as retryable, so a genuinely broken recorder announces itself
    /// as three identical failures rather than as one confusing one.
    fn gateway(message: String) -> Self {
        let body = serde_json::json!({ "error": message }).to_string();
        Self {
            status: 502,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: body.into_bytes(),
        }
    }
}

/// The request line and its headers. Only GETs reach here, so there is no body
/// to read past the blank line.
async fn read_head(socket: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        if socket.read(&mut byte).await? == 0 {
            return Ok(None);
        }
        raw.push(byte[0]);
        // A presigned URL comes back hex-encoded in a path, so the request line
        // is legitimately long; anything past this is not a request at all.
        if raw.len() > 64 * 1024 {
            return Ok(None);
        }
    }

    let text = String::from_utf8_lossy(&raw);
    let mut lines = text.lines();
    let Some(target) = lines.next().and_then(|line| line.split_whitespace().nth(1)) else {
        return Ok(None);
    };
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_lowercase(), value.trim().to_owned()));
        }
    }
    Ok(Some(Request { target: target.to_owned(), headers }))
}

async fn write_reply(socket: &mut TcpStream, reply: &Reply) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reply.body.len()
    );
    for (name, value) in &reply.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    socket.write_all(head.as_bytes()).await?;
    socket.write_all(&reply.body).await?;
    socket.flush().await?;
    socket.shutdown().await
}

/// A URL's origin and its path, with the query dropped. Hand-split rather than
/// parsed: a test asserts about the host a request went to and the path it
/// asked for, and a query string carrying a presigned signature is exactly what
/// must not end up in either.
fn split(url: &str) -> (String, String) {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = path.split('?').next().unwrap_or("");
    (format!("{scheme}://{host}"), format!("/{path}"))
}

/// Hex rather than base64 or percent-encoding, because the result becomes a path
/// segment and hex has no character that has to be escaped again on the way
/// through.
fn to_hex(value: &str) -> String {
    value.bytes().map(|byte| format!("{byte:02x}")).collect()
}

fn from_hex(value: &str) -> String {
    let bytes: Vec<u8> = value
        .as_bytes()
        .chunks(2)
        .filter_map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
