//! Capped Electrum transport: every connection paykit-server opens to the
//! configured Electrum endpoint is built here and nowhere else.
//!
//! electrum-client 0.25's `RawClient::_reader_thread` buffers each
//! newline-delimited JSON-RPC response with an unbounded
//! `BufReader::read_line` before any decode or item-count cap can run, but
//! its `From<S: Read + Write>` constructor accepts ANY stream type and
//! `ElectrumApi` is implemented for `RawClient<S>`. Wrapping the TCP/TLS
//! stream in [`CappedStream`] therefore fails the read BEFORE `BufReader`
//! grows or JSON is decoded: no single Electrum response line larger than
//! `electrum.max_response_bytes` is ever held in memory. When a line
//! exceeds the cap the stream returns the literal
//! [`RESPONSE_CAP_ERROR_MESSAGE`] `io::Error` and poisons itself, so the
//! half-read line can never be resumed: the caller must drop the client
//! and reconnect. Reconnects send no handshake RPC (the TLS handshake is
//! transport I/O, not an Electrum request, and `RawClient::from` performs
//! no `server.version` negotiation), so a reconnect is not a budgeted
//! send.
//!
//! TLS endpoints (`ssl://`) are built with rustls and the webpki root
//! store with certificate validation ON. There is no `validate_domain`
//! switch and no custom certificate verifier anywhere in this tree: a
//! bad certificate fails the handshake, full stop. `tcp://` is plaintext with
//! no server authentication (accepted for regtest/local endpoints).
//! Anything else — including `socks5://` — is refused at parse time; the
//! proxy feature of electrum-client is intentionally not routed through
//! this wrapper.

use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use electrum_client::raw_client::RawClient;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{Der, ServerName, TrustAnchor},
};

/// Literal `io::Error` message returned when one response line exceeds
/// `electrum.max_response_bytes`; asserted by tests and greppable by
/// operators.
pub const RESPONSE_CAP_ERROR_MESSAGE: &str = "electrum response exceeds max_response_bytes";

/// Literal `io::Error` message for an endpoint whose scheme is not
/// `tcp://` or `ssl://` (including `socks5://`).
pub const ENDPOINT_SCHEME_ERROR_MESSAGE: &str = "electrum endpoint scheme must be tcp:// or ssl://";

/// Default `electrum.max_response_bytes`: 1 MiB.
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// Floor for `electrum.max_response_bytes`: 64 KiB. Startup refuses a
/// smaller value.
pub const MIN_MAX_RESPONSE_BYTES: u64 = 64 * 1024;

/// Wire-size upper bound for one `blockchain.scripthash.listunspent`
/// item: `{"tx_hash":"<64 hex>","tx_pos":<u32>,"height":<u32>,`
/// `"value":<u64>}` — 64 hex characters plus the field names, JSON
/// punctuation, and the longest u32/u64 digit strings stays under 110
/// bytes. Config validation refuses an `electrum.max_utxos_per_address`
/// whose maximum reply (items × this bound, plus the JSON-RPC envelope)
/// would exceed `electrum.max_response_bytes`, so the item cap can
/// never demand a response the transport byte cap refuses.
pub const LISTUNSPENT_ITEM_BYTES_UPPER_BOUND: u64 = 110;

/// Ceiling for `electrum.max_response_bytes`: 16 MiB. Startup refuses a
/// larger value. Justification from the design's own caps: the largest
/// legitimate response this process ever reads is one
/// `blockchain.scripthash.listunspent` reply of at most
/// `electrum.max_utxos_per_address` items (default 200) of at most
/// [`LISTUNSPENT_ITEM_BYTES_UPPER_BOUND`] bytes each, so the default
/// configuration's largest response is ≈ 21 KiB and even a
/// 100 000-item configuration stays under ~11 MiB. The only other
/// responses are the tick's probe replies (`headers.subscribe` and
/// `block_header(0)`: an 80-byte header hex-encoded plus envelope, well
/// under 1 KiB). 16 MiB therefore bounds every legitimate response with
/// headroom while keeping the per-line memory bound tight.
pub const MAX_MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

fn response_cap_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, RESPONSE_CAP_ERROR_MESSAGE)
}

/// A `Read + Write` transport stream with a hard per-line byte cap on
/// reads. The Electrum JSON-RPC protocol is newline-delimited, so the cap
/// is tracked per line: bytes since the last newline. When a single line
/// exceeds `max_response_bytes` the read delivers only the complete lines
/// preceding the oversize one (or fails outright when there are none) and
/// the stream poisons itself: every later read fails with
/// [`RESPONSE_CAP_ERROR_MESSAGE`]. A poisoned stream can never resume a
/// half-read line; the connection must be torn down and re-established by
/// the caller. Each read requests at most the current line's remaining
/// budget plus one byte from the inner stream, so a poisoned line of ANY
/// length consumes exactly `max_response_bytes + 1` bytes from the source
/// before the read fails — never more. Writes pass through uncapped
/// (requests are small and self-generated).
///
/// `CappedStream<S>` is `Send + 'static` whenever `S` is, so it can cross
/// into the blocking pool inside `RawClient`. `RawClient` requires no
/// `Clone` on `S`: it wraps the stream in its own `Arc<Mutex<_>>`
/// (`ClonableStream`) internally.
pub struct CappedStream<S: Read + Write> {
    inner: S,
    max_response_bytes: u64,
    /// Bytes read since the last newline (the current line's length so
    /// far, excluding the newline itself, which is never counted against
    /// the cap: a line whose content is exactly `max_response_bytes`
    /// bytes before its newline terminator succeeds).
    line_bytes: u64,
    poisoned: bool,
}

impl<S: Read + Write> CappedStream<S> {
    pub fn new(inner: S, max_response_bytes: u64) -> Self {
        Self {
            inner,
            max_response_bytes,
            line_bytes: 0,
            poisoned: false,
        }
    }
}

impl<S: Read + Write> Read for CappedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.poisoned {
            return Err(response_cap_error());
        }
        // Never request more than the current line's remaining budget
        // plus one byte from the inner stream: without the clamp an
        // oversize line would be consumed (and held in the caller's
        // buffer) up to the caller's buffer size before the cap check
        // below runs. With it, the byte AFTER the cap is the last byte
        // ever consumed for a poisoned line — an over-cap line of any
        // length costs the source exactly `max_response_bytes + 1` bytes
        // of consumption before the read fails.
        // The subtraction cannot underflow: an unpoisoned stream holds
        // at most `max_response_bytes` bytes for the current line,
        // because the check below poisons the stream and returns the
        // error on the very increment that would push it over.
        debug_assert!(
            self.line_bytes <= self.max_response_bytes,
            "an unpoisoned stream never holds more than the cap for the current line"
        );
        let remaining_line_budget = self.max_response_bytes - self.line_bytes;
        let clamped_len = (remaining_line_budget + 1).min(buf.len() as u64) as usize;
        let n = self.inner.read(&mut buf[..clamped_len])?;
        for (index, &byte) in buf[..n].iter().enumerate() {
            if byte == b'\n' {
                self.line_bytes = 0;
                continue;
            }
            self.line_bytes += 1;
            if self.line_bytes > self.max_response_bytes {
                // The current line exceeds the cap. Poison first so no
                // later read can resume it, then hand back only the
                // complete lines that precede it; with none to deliver,
                // fail the read itself so no partial oversize line ever
                // reaches the client's buffer (no JSON decode is
                // attempted).
                self.poisoned = true;
                let delivered = buf[..index]
                    .iter()
                    .rposition(|&b| b == b'\n')
                    .map_or(0, |position| position + 1);
                if delivered == 0 {
                    return Err(response_cap_error());
                }
                return Ok(delivered);
            }
        }
        Ok(n)
    }
}

impl<S: Read + Write> Write for CappedStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Object-safe transport bound: the concrete stream behind a connection
/// (`TcpStream` or rustls `StreamOwned`) is boxed so the client type is
/// the same for `tcp://` and `ssl://` endpoints.
pub trait IoStream: Read + Write + Send + 'static {}

impl<T: Read + Write + Send + 'static> IoStream for T {}

/// The one Electrum client type this process uses: a `RawClient` over a
/// byte-capped transport. `ElectrumApi` (including `raw_call` and
/// `batch_call`) is implemented for it by electrum-client.
pub type CappedClient = RawClient<CappedStream<Box<dyn IoStream>>>;

/// A parsed `tcp://host:port` or `ssl://host:port` endpoint. Any other
/// scheme — including `socks5://` — is refused with
/// [`ENDPOINT_SCHEME_ERROR_MESSAGE`]: the proxy transport is deliberately
/// not routed through the capped wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElectrumEndpoint {
    use_tls: bool,
    host: String,
    port: u16,
}

impl ElectrumEndpoint {
    pub fn parse(endpoint: &str) -> Result<Self, io::Error> {
        let parsed = url::Url::parse(endpoint).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, ENDPOINT_SCHEME_ERROR_MESSAGE)
        })?;
        let use_tls = match parsed.scheme() {
            "tcp" => false,
            "ssl" => true,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    ENDPOINT_SCHEME_ERROR_MESSAGE,
                ));
            }
        };
        let host = parsed.host_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, ENDPOINT_SCHEME_ERROR_MESSAGE)
        })?;
        let port = parsed.port().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, ENDPOINT_SCHEME_ERROR_MESSAGE)
        })?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || !matches!(parsed.path(), "" | "/")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                ENDPOINT_SCHEME_ERROR_MESSAGE,
            ));
        }
        Ok(Self {
            use_tls,
            host: host.to_owned(),
            port,
        })
    }
}

/// Opens one capped Electrum connection: endpoint parse, TCP connect with
/// `connect_timeout`, read/write timeouts of `timeout`, TLS for `ssl://`
/// endpoints, then `RawClient::from(CappedStream::new(stream, cap))`.
/// Performs NO Electrum RPC: the TLS handshake is transport I/O, not an
/// Electrum request, and `RawClient::from` does not negotiate
/// `server.version`, so building this connection is never a budgeted
/// send.
pub fn connect(
    endpoint: &str,
    timeout: Duration,
    max_response_bytes: u64,
) -> io::Result<CappedClient> {
    let endpoint = ElectrumEndpoint::parse(endpoint)?;
    let mut last_error = None;
    let mut tcp = None;
    for address in (endpoint.host.as_str(), endpoint.port).to_socket_addrs()? {
        match connect_tcp(address, timeout) {
            Ok(stream) => {
                tcp = Some(stream);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let tcp = tcp.ok_or_else(|| {
        last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address resolved"))
    })?;
    let stream: Box<dyn IoStream> = if endpoint.use_tls {
        Box::new(tls_stream(&endpoint.host, tcp)?)
    } else {
        Box::new(tcp)
    };
    Ok(RawClient::from(CappedStream::new(
        stream,
        max_response_bytes,
    )))
}

fn connect_tcp(address: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

/// Builds the TLS transport with certificate validation ON: the webpki
/// root store, SNI = endpoint host, and no custom verifier — there is no
/// `validate_domain = false` path to reach.
fn tls_stream(host: &str, tcp: TcpStream) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Mirror electrum-client's rustls-ring setup: install the ring
        // provider process-wide so `ClientConfig::builder` has a default.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    // webpki-roots 0.25 vendors its own TrustAnchor type, so map into
    // rustls-pki-types field by field, exactly as electrum-client's
    // rustls-ring path does.
    let roots: RootCertStore = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .map(|anchor| TrustAnchor {
            subject: Der::from_slice(anchor.subject),
            subject_public_key_info: Der::from_slice(anchor.spki),
            name_constraints: anchor.name_constraints.map(Der::from_slice),
        })
        .collect();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_owned()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "electrum endpoint host is not a valid TLS server name",
        )
    })?;
    let connection =
        ClientConnection::new(Arc::new(config), server_name).map_err(io::Error::other)?;
    Ok(StreamOwned::new(connection, tcp))
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, Cursor},
        net::TcpListener,
        sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
        thread,
    };

    use electrum_client::{ElectrumApi, Param};

    use super::*;

    const CAP: u64 = 64;

    fn capped_cursor(bytes: &[u8]) -> CappedStream<Cursor<Vec<u8>>> {
        CappedStream::new(Cursor::new(bytes.to_vec()), CAP)
    }

    fn read_to_end<S: Read + Write>(stream: &mut CappedStream<S>) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        stream.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn the_capped_stream_is_send_and_static() {
        fn assert_send_static<T: Send + 'static>() {}
        assert_send_static::<CappedStream<TcpStream>>();
        assert_send_static::<CappedStream<Box<dyn IoStream>>>();
        assert_send_static::<CappedClient>();
    }

    #[test]
    fn a_line_of_exactly_cap_bytes_including_the_newline_succeeds() {
        // cap - 1 content bytes + the newline = exactly CAP bytes.
        let mut line = vec![b'x'; (CAP - 1) as usize];
        line.push(b'\n');
        let mut stream = capped_cursor(&line);
        let read = read_to_end(&mut stream).expect("exactly cap bytes incl. newline passes");
        assert_eq!(read, line);
        // The newline resets the counter: the next line starts fresh.
        let mut stream = capped_cursor(&[line.clone(), line.clone()].concat());
        assert_eq!(
            read_to_end(&mut stream).unwrap().len(),
            2 * line.len(),
            "two exactly-cap lines both pass"
        );
    }

    #[test]
    fn a_line_with_exactly_cap_content_bytes_before_the_newline_succeeds() {
        // CAP content bytes + the newline: the newline is never counted
        // against the cap, so the line is exactly AT the cap and must be
        // delivered intact, not poisoned.
        let mut line = vec![b'x'; CAP as usize];
        line.push(b'\n');
        let mut stream = capped_cursor(&line);
        let read = read_to_end(&mut stream).expect("exactly cap content bytes pass");
        assert_eq!(read, line);
        // Not poisoned: the next read sees a clean EOF, not the cap error.
        assert_eq!(stream.read(&mut [0u8; 8]).unwrap(), 0);
    }

    #[test]
    fn an_exactly_cap_line_followed_by_a_small_line_in_one_burst_both_pass() {
        let mut exact = vec![b'x'; CAP as usize];
        exact.push(b'\n');
        let small = b"{\"id\":0,\"result\":[]}\n".to_vec();
        let burst = [exact, small].concat();
        let mut stream = capped_cursor(&burst);
        let read = read_to_end(&mut stream).expect("both lines are delivered");
        assert_eq!(read, burst);
    }

    #[test]
    fn a_line_of_cap_plus_one_content_bytes_fails_with_the_literal_message_and_poisons() {
        // CAP + 1 content bytes: one byte over the cap, the smallest
        // line the cap must reject.
        let mut line = vec![b'x'; (CAP + 1) as usize];
        line.push(b'\n');
        let mut stream = capped_cursor(&line);
        let error = stream.read(&mut [0u8; 256]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), RESPONSE_CAP_ERROR_MESSAGE);
        // Poisoned: every later read fails with the same literal error;
        // the half-read line can never be resumed.
        let error = stream.read(&mut [0u8; 256]).unwrap_err();
        assert_eq!(error.to_string(), RESPONSE_CAP_ERROR_MESSAGE);
    }

    #[test]
    fn a_multi_line_burst_fails_only_at_the_oversize_line() {
        let small = b"{\"id\":0,\"result\":[]}\n".to_vec();
        assert!((small.len() as u64) < CAP);
        // Far larger than the cap so the source-consumption clamp (not
        // the burst length) is what stops the read.
        let mut oversize = vec![b'x'; (CAP + 4096) as usize];
        oversize.push(b'\n');
        let burst = [small.clone(), oversize].concat();
        let mut stream = capped_cursor(&burst);
        let mut buf = [0u8; 512];
        // Reads deliver the complete small line (followed by at most a
        // clamped prefix of the oversize one); the oversize line's
        // newline is never consumed — the read fails with the literal
        // cap error first.
        let mut delivered = Vec::new();
        loop {
            match stream.read(&mut buf) {
                Ok(0) => panic!("the stream ended before the cap error"),
                Ok(n) => delivered.extend_from_slice(&buf[..n]),
                Err(error) => {
                    assert_eq!(error.to_string(), RESPONSE_CAP_ERROR_MESSAGE);
                    break;
                }
            }
        }
        assert!(
            delivered.starts_with(&small),
            "the small line is delivered intact"
        );
        assert!(
            delivered.len() <= small.len() + (CAP + 1) as usize,
            "at most cap + 1 bytes of the oversize line are ever delivered"
        );
        // Poisoned: every later read fails with the same literal error.
        let error = stream.read(&mut buf).unwrap_err();
        assert_eq!(error.to_string(), RESPONSE_CAP_ERROR_MESSAGE);
        // Writes pass through uncapped even after poisoning.
        assert_eq!(stream.write(b"request\n").unwrap(), 8);
    }

    /// A `Read + Write` source that counts the total bytes ever consumed
    /// from it, proving the clamp bounds what a poisoned line costs.
    struct CountingStream {
        inner: Cursor<Vec<u8>>,
        consumed: usize,
    }

    impl Read for CountingStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.consumed += n;
            Ok(n)
        }
    }

    impl Write for CountingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn an_over_cap_line_consumes_exactly_cap_plus_one_bytes_from_the_source() {
        // CAP + 4096 content bytes, then a newline that must never be
        // consumed: the cap trips first.
        let mut line = vec![b'x'; (CAP + 4096) as usize];
        line.push(b'\n');
        let mut stream = CappedStream::new(
            CountingStream {
                inner: Cursor::new(line),
                consumed: 0,
            },
            CAP,
        );
        let mut buf = [0u8; 8192];
        let error = loop {
            match stream.read(&mut buf) {
                Ok(delivered) => {
                    assert!(delivered > 0, "the source never EOFs before the cap trips");
                }
                Err(error) => break error,
            }
        };
        assert_eq!(error.to_string(), RESPONSE_CAP_ERROR_MESSAGE);
        assert_eq!(
            stream.inner.consumed,
            (CAP + 1) as usize,
            "a poisoned line costs the source exactly cap + 1 bytes, never cap + N"
        );
    }

    #[test]
    fn endpoint_schemes_other_than_tcp_and_ssl_are_refused_with_the_literal_message() {
        for endpoint in [
            "socks5://127.0.0.1:9050",
            "http://electrum.example:50002",
            "electrum.example:50001",
        ] {
            let error = ElectrumEndpoint::parse(endpoint).unwrap_err();
            assert_eq!(
                error.to_string(),
                ENDPOINT_SCHEME_ERROR_MESSAGE,
                "{endpoint}"
            );
        }
        let parsed = ElectrumEndpoint::parse("tcp://127.0.0.1:50001").unwrap();
        assert!(!parsed.use_tls && parsed.host == "127.0.0.1" && parsed.port == 50001);
        let parsed = ElectrumEndpoint::parse("ssl://electrum.example:50002").unwrap();
        assert!(parsed.use_tls && parsed.host == "electrum.example" && parsed.port == 50002);
    }

    /// One in-process fake Electrum server over a real 127.0.0.1 TCP
    /// listener with deterministic shutdown: the accept loop is
    /// nonblocking behind a stop flag and every spawned thread (acceptor
    /// and per-connection handlers) is joined on drop, so a failing test
    /// can never leak a listener thread.
    struct FakeServer {
        endpoint: String,
        stop: Arc<AtomicBool>,
        accept_handle: Option<thread::JoinHandle<()>>,
        connection_handles: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    }

    impl FakeServer {
        /// Serves `small` for the first request on the first connection,
        /// then `oversize` for the second request on that same
        /// connection. A fresh connection answers `small` again: this is
        /// the reconnect path.
        fn start(small: String, oversize: String) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let endpoint = format!("tcp://{}", listener.local_addr().unwrap());
            let stop = Arc::new(AtomicBool::new(false));
            let connection_handles: Arc<Mutex<Vec<thread::JoinHandle<()>>>> =
                Arc::new(Mutex::new(Vec::new()));
            let accept_handle = {
                let stop = Arc::clone(&stop);
                let connection_handles = Arc::clone(&connection_handles);
                thread::spawn(move || {
                    let mut connections = 0_u32;
                    while !stop.load(Ordering::Relaxed) {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                connections += 1;
                                let first = connections == 1;
                                let small = small.clone();
                                let oversize = oversize.clone();
                                let handle = thread::spawn(move || {
                                    Self::serve(stream, first, &small, &oversize);
                                });
                                connection_handles.lock().unwrap().push(handle);
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(5));
                            }
                            Err(_) => return,
                        }
                    }
                })
            };
            Self {
                endpoint,
                stop,
                accept_handle: Some(accept_handle),
                connection_handles,
            }
        }

        /// Answers request lines until client EOF. The read-timeout
        /// backstop guarantees the handler exits even if a test fails
        /// while its client connection is still open, so the drop-time
        /// join can never wedge.
        fn serve(stream: TcpStream, first: bool, small: &str, oversize: &str) {
            // Accepted sockets inherit the listener's nonblocking flag
            // on some platforms (e.g. macOS); the handler needs a
            // blocking socket behind its read-timeout backstop.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            let mut answered = 0_u32;
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let id: serde_json::Value = serde_json::from_str::<serde_json::Value>(&line)
                    .unwrap()
                    .get("id")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                answered += 1;
                let result = if first && answered == 2 {
                    oversize
                } else {
                    small
                };
                let response = format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{result}}}\n");
                if writer.write_all(response.as_bytes()).is_err() {
                    return;
                }
                let _ = writer.flush();
            }
        }
    }

    impl Drop for FakeServer {
        fn drop(&mut self) {
            // Deterministic shutdown: flag the accept loop (it observes
            // the flag within one 5 ms poll), join it, then join every
            // connection handler. Handlers exit on client EOF (clients
            // drop before the server in every test) or on the
            // read-timeout backstop, so the joins always return. No
            // thread is left detached.
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.accept_handle.take() {
                let _ = handle.join();
            }
            let handles = std::mem::take(&mut *self.connection_handles.lock().unwrap());
            for handle in handles {
                let _ = handle.join();
            }
        }
    }

    fn small_result_line() -> String {
        serde_json::json!([]).to_string()
    }

    fn oversize_result_line() -> String {
        // A result payload sized so the full response line's content is
        // CAP + 1 bytes before its newline (the second request on a
        // connection has id 1): the smallest line the cap must reject.
        let wrapper = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"\"}\n";
        let pad = (CAP as usize + 2).saturating_sub(wrapper.len());
        format!("\"{}\"", "y".repeat(pad))
    }

    #[test]
    fn the_fake_server_shuts_down_deterministically() {
        // Dropping the server joins the accept thread and every
        // connection handler: this test completing at all proves a
        // failing test can never leak a listener thread or hang the
        // test process on shutdown.
        let server = FakeServer::start(small_result_line(), oversize_result_line());
        let client = connect(&server.endpoint, Duration::from_secs(5), CAP)
            .expect("connect to the fake server");
        let first = client
            .raw_call(
                "blockchain.scripthash.listunspent",
                [Param::String("aa".into())],
            )
            .expect("small response succeeds");
        assert_eq!(first, serde_json::json!([]));
        drop(client);
        drop(server);
    }

    #[test]
    fn an_oversize_response_fails_before_decode_and_the_reconnect_succeeds() {
        let server = FakeServer::start(small_result_line(), oversize_result_line());
        let mut client = connect(&server.endpoint, Duration::from_secs(5), CAP)
            .expect("connect to the fake server");

        // First request: small response line, decodes normally.
        let first = client
            .raw_call(
                "blockchain.scripthash.listunspent",
                [Param::String("aa".into())],
            )
            .expect("small response succeeds");
        assert_eq!(first, serde_json::json!([]));

        // Second request on the same connection: cap + n bytes. The
        // client's BufReader never sees the oversize line — the read
        // fails with the literal cap error, so no JSON decode is
        // attempted (a decode attempt would surface a serde error, not
        // this message).
        let error = client
            .raw_call(
                "blockchain.scripthash.listunspent",
                [Param::String("bb".into())],
            )
            .unwrap_err();
        assert!(
            error.to_string().contains(RESPONSE_CAP_ERROR_MESSAGE),
            "expected the literal cap error, got: {error}"
        );

        // The poisoned stream fails every later read: the caller tears
        // the connection down (drop) and reconnects; the fresh
        // connection's next request succeeds.
        drop(client);
        client = connect(&server.endpoint, Duration::from_secs(5), CAP)
            .expect("reconnect to the fake server");
        let third = client
            .raw_call(
                "blockchain.scripthash.listunspent",
                [Param::String("cc".into())],
            )
            .expect("the request after reconnect succeeds");
        assert_eq!(third, serde_json::json!([]));
    }
}
