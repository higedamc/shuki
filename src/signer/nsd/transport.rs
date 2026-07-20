//! Serial transport abstraction + `serialport` impl + scripted mock for tests
//! (owned by `leaf/signer-nsd-serial`).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::error::{Result, ShukiError};

use super::protocol;

/// NSD firmware fixed baud rate.
pub const NSD_BAUD_RATE: u32 = 9600;

/// How long a single blocking `serialport` read waits before we re-check the
/// caller's deadline.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Upper bound on buffered bytes while waiting for a newline. Legitimate NSD
/// responses are < 200 bytes; a peer streaming data without newlines (broken
/// or hostile device/PTY) must not grow host memory unboundedly.
const MAX_LINE_BYTES: usize = 8192;

/// Enforce [`MAX_LINE_BYTES`] on a receive buffer (call after every append).
fn check_line_cap(buf: &mut Vec<u8>) -> Result<()> {
    if buf.len() > MAX_LINE_BYTES {
        buf.clear();
        return Err(ShukiError::Device(format!(
            "device sent more than {MAX_LINE_BYTES} bytes without a newline"
        )));
    }
    Ok(())
}

/// Minimal line-oriented serial transport. One command in flight at a time;
/// the owner (the NSD worker thread) serializes access.
pub trait SerialTransport: Send {
    /// Write `line` followed by `\n` and flush.
    fn write_line(&mut self, line: &str) -> Result<()>;

    /// Read the next complete line (newline stripped, CRLF tolerated).
    /// `Ok(None)` means no complete line arrived within `timeout`.
    fn read_line(&mut self, timeout: Duration) -> Result<Option<String>>;
}

// ---------------------------------------------------------------------------
// Real serialport-backed implementation
// ---------------------------------------------------------------------------

/// [`SerialTransport`] over a real serial port (9600 baud, 8N1).
pub struct SerialPortTransport {
    port: Box<dyn serialport::SerialPort>,
    /// Bytes received but not yet terminated by `\n`.
    buf: Vec<u8>,
}

impl SerialPortTransport {
    /// Open `path` with the NSD's fixed settings (9600 baud, 8N1, no flow
    /// control). Short per-read timeouts are accumulated into the caller's
    /// deadline inside [`SerialTransport::read_line`].
    pub fn open(path: &str) -> Result<Self> {
        let port = serialport::new(path, NSD_BAUD_RATE)
            .data_bits(serialport::DataBits::Eight)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .flow_control(serialport::FlowControl::None)
            .timeout(POLL_INTERVAL)
            .open()
            .map_err(|e| ShukiError::Device(format!("open serial port {path}: {e}")))?;
        Ok(Self {
            port,
            buf: Vec::new(),
        })
    }

    /// Pop one complete line off the internal buffer, if any.
    fn take_buffered_line(&mut self) -> Option<String> {
        let pos = self.buf.iter().position(|&b| b == b'\n')?;
        let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
        line.pop(); // '\n'
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Some(String::from_utf8_lossy(&line).into_owned())
    }
}

impl SerialTransport for SerialPortTransport {
    fn write_line(&mut self, line: &str) -> Result<()> {
        use std::io::Write;
        self.port
            .write_all(line.as_bytes())
            .and_then(|()| self.port.write_all(b"\n"))
            .and_then(|()| self.port.flush())
            .map_err(|e| ShukiError::Device(format!("serial write: {e}")))
    }

    fn read_line(&mut self, timeout: Duration) -> Result<Option<String>> {
        use std::io::Read;
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(line) = self.take_buffered_line() {
                return Ok(Some(line));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            let mut chunk = [0u8; 256];
            match self.port.read(&mut chunk) {
                Ok(0) => {} // treated like a poll timeout; loop until deadline
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    check_line_cap(&mut self.buf)?;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(ShukiError::Device(format!("serial read: {e}"))),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PTY fallback (test rigs without real hardware)
// ---------------------------------------------------------------------------

/// [`SerialTransport`] over a raw file handle in non-blocking mode.
///
/// Fallback for PTYs (e.g. a `socat` pair driving the `fake_nsd` example):
/// the `serialport` crate's baud-rate ioctls fail with `ENOTTY` on pseudo
/// terminals, but plain non-blocking file IO works fine there. Real devices
/// keep using [`SerialPortTransport`].
pub struct PtyFileTransport {
    file: std::fs::File,
    buf: Vec<u8>,
}

impl PtyFileTransport {
    pub fn open(path: &str) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| ShukiError::Device(format!("open pty {path}: {e}")))?;
        Ok(Self {
            file,
            buf: Vec::new(),
        })
    }

    fn take_buffered_line(&mut self) -> Option<String> {
        let pos = self.buf.iter().position(|&b| b == b'\n')?;
        let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Some(String::from_utf8_lossy(&line).into_owned())
    }
}

impl SerialTransport for PtyFileTransport {
    fn write_line(&mut self, line: &str) -> Result<()> {
        use std::io::Write;
        let mut data = line.as_bytes().to_vec();
        data.push(b'\n');
        let mut written = 0;
        while written < data.len() {
            match self.file.write(&data[written..]) {
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(ShukiError::Device(format!("pty write: {e}"))),
            }
        }
        Ok(())
    }

    fn read_line(&mut self, timeout: Duration) -> Result<Option<String>> {
        use std::io::Read;
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(line) = self.take_buffered_line() {
                return Ok(Some(line));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            let mut chunk = [0u8; 256];
            match self.file.read(&mut chunk) {
                Ok(0) => std::thread::sleep(Duration::from_millis(10)),
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    check_line_cap(&mut self.buf)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(ShukiError::Device(format!("pty read: {e}"))),
            }
        }
    }
}

/// Open `path` as a serial device, falling back to raw PTY file IO when the
/// serialport crate cannot handle it (pseudo terminals).
pub fn open_port(path: &str) -> Result<Box<dyn SerialTransport>> {
    match SerialPortTransport::open(path) {
        Ok(t) => Ok(Box::new(t)),
        Err(serial_err) => match PtyFileTransport::open(path) {
            Ok(t) => {
                tracing::debug!(port = %path, "serialport open failed; using raw pty file IO");
                Ok(Box::new(t))
            }
            Err(_) => Err(serial_err),
        },
    }
}

// ---------------------------------------------------------------------------
// Autodetection
// ---------------------------------------------------------------------------

/// Enumerate serial ports and `/ping` each until an NSD answers.
///
/// USB ports are probed first (the NSD is a USB CDC device), the rest after.
/// Returns the port name and the already-open transport so the device is not
/// reset by a re-open. Thin by design; not unit-tested against hardware.
pub fn autodetect(ping_timeout: Duration) -> Result<(String, SerialPortTransport)> {
    let ports = serialport::available_ports()
        .map_err(|e| ShukiError::Device(format!("enumerate serial ports: {e}")))?;
    let (usb, other): (Vec<_>, Vec<_>) = ports
        .into_iter()
        .partition(|p| matches!(p.port_type, serialport::SerialPortType::UsbPort(_)));

    let mut tried: Vec<String> = Vec::new();
    for info in usb.into_iter().chain(other) {
        let name = info.port_name;
        tried.push(name.clone());
        let mut transport = match SerialPortTransport::open(&name) {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(port = %name, error = %e, "nsd autodetect: cannot open, skipping");
                continue;
            }
        };
        if probe_ping(&mut transport, ping_timeout) {
            tracing::info!(port = %name, "nsd autodetect: device answered ping");
            return Ok((name, transport));
        }
        tracing::debug!(port = %name, "nsd autodetect: no ping answer");
    }
    Err(ShukiError::Device(format!(
        "no NSD answered on any serial port (tried: {tried:?})"
    )))
}

/// Send one `/ping` and wait for a valid answer, skipping noise lines.
pub(crate) fn probe_ping(transport: &mut dyn SerialTransport, timeout: Duration) -> bool {
    if transport
        .write_line(&protocol::frame_ping("shuki-probe"))
        .is_err()
    {
        return false;
    }
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match transport.read_line(remaining) {
            Ok(Some(line)) => {
                if let Some(payload) = protocol::parse_line(protocol::CMD_PING, &line) {
                    if protocol::parse_ping_payload(payload).is_some() {
                        return true;
                    }
                }
            }
            Ok(None) | Err(_) => return false,
        }
    }
}

// ---------------------------------------------------------------------------
// Scripted mock for tests
// ---------------------------------------------------------------------------

/// One scripted line delivered by [`MockTransport::read_line`].
#[derive(Debug, Clone)]
pub enum MockLine {
    /// A complete line (as the device would send, newline already stripped).
    Line(String),
    /// Simulate the read deadline elapsing with no line (`Ok(None)`).
    Timeout,
    /// Simulate the device disappearing mid-read (IO error).
    Disconnect,
}

impl MockLine {
    /// Convenience constructor.
    pub fn line(s: impl Into<String>) -> Self {
        Self::Line(s.into())
    }
}

/// What an exchange expects the host to write.
#[derive(Debug, Clone)]
enum ExpectWrite {
    Exact(String),
    Prefix(String),
}

#[derive(Debug, Clone)]
struct MockExchange {
    expect: ExpectWrite,
    responses: Vec<MockLine>,
}

/// Scripted [`SerialTransport`]: an ordered queue of
/// expected-write → canned-response-lines exchanges, plus modes for timeout
/// and disconnect. An unexpected or unscripted write returns an error, which
/// surfaces through the signer as a failed request.
#[derive(Debug, Default)]
pub struct MockTransport {
    script: VecDeque<MockExchange>,
    pending: VecDeque<MockLine>,
    fail_writes: bool,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Expect exactly `write`; when it arrives, queue `responses` for reads.
    #[must_use]
    pub fn expect(mut self, write: impl Into<String>, responses: Vec<MockLine>) -> Self {
        self.script.push_back(MockExchange {
            expect: ExpectWrite::Exact(write.into()),
            responses,
        });
        self
    }

    /// Expect a write starting with `prefix` (e.g. `"/ping "` whose token is
    /// generated at runtime); when it arrives, queue `responses`.
    #[must_use]
    pub fn expect_prefix(mut self, prefix: impl Into<String>, responses: Vec<MockLine>) -> Self {
        self.script.push_back(MockExchange {
            expect: ExpectWrite::Prefix(prefix.into()),
            responses,
        });
        self
    }

    /// Every write fails as if the device was unplugged.
    #[must_use]
    pub fn with_failing_writes(mut self) -> Self {
        self.fail_writes = true;
        self
    }

    /// Box up for [`super::NsdSigner::with_transport`].
    pub fn boxed(self) -> Box<dyn SerialTransport> {
        Box::new(self)
    }
}

impl SerialTransport for MockTransport {
    fn write_line(&mut self, line: &str) -> Result<()> {
        if self.fail_writes {
            return Err(ShukiError::Device("mock: write failed (unplugged)".into()));
        }
        match self.script.pop_front() {
            Some(ex) => {
                let ok = match &ex.expect {
                    ExpectWrite::Exact(want) => line == want,
                    ExpectWrite::Prefix(prefix) => line.starts_with(prefix.as_str()),
                };
                if !ok {
                    return Err(ShukiError::Device(format!(
                        "mock: unexpected write {line:?}, expected {:?}",
                        ex.expect
                    )));
                }
                self.pending.extend(ex.responses);
                Ok(())
            }
            None => Err(ShukiError::Device(format!(
                "mock: unexpected write {line:?}, script exhausted"
            ))),
        }
    }

    fn read_line(&mut self, _timeout: Duration) -> Result<Option<String>> {
        match self.pending.pop_front() {
            Some(MockLine::Line(l)) => Ok(Some(l)),
            Some(MockLine::Timeout) | None => Ok(None),
            Some(MockLine::Disconnect) => {
                Err(ShukiError::Device("mock: device disconnected".into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Duration = Duration::from_millis(10);

    #[test]
    fn line_cap_bounds_hostile_stream() {
        let mut buf = vec![0u8; MAX_LINE_BYTES];
        assert!(check_line_cap(&mut buf).is_ok());
        buf.push(0);
        let err = check_line_cap(&mut buf).unwrap_err();
        assert!(matches!(err, ShukiError::Device(_)), "got: {err:?}");
        assert!(buf.is_empty(), "oversized buffer must be discarded");
    }

    #[test]
    fn mock_scripted_exchange() {
        let mut mock = MockTransport::new().expect(
            "/public-key",
            vec![
                MockLine::line("/log booting"),
                MockLine::line("/public-key abc123"),
            ],
        );
        mock.write_line("/public-key").unwrap();
        assert_eq!(mock.read_line(T).unwrap().as_deref(), Some("/log booting"));
        assert_eq!(
            mock.read_line(T).unwrap().as_deref(),
            Some("/public-key abc123")
        );
        // queue drained → behaves like a timeout
        assert_eq!(mock.read_line(T).unwrap(), None);
    }

    #[test]
    fn mock_rejects_unexpected_write() {
        let mut mock = MockTransport::new().expect("/public-key", vec![]);
        assert!(mock.write_line("/ping x").is_err());
        // script exhausted afterwards
        assert!(mock.write_line("/public-key").is_err());
    }

    #[test]
    fn mock_prefix_matching() {
        let mut mock =
            MockTransport::new().expect_prefix("/ping ", vec![MockLine::line("/ping 0 dev-1")]);
        mock.write_line("/ping 1a2b3c").unwrap();
        assert_eq!(mock.read_line(T).unwrap().as_deref(), Some("/ping 0 dev-1"));
    }

    #[test]
    fn mock_timeout_and_disconnect_modes() {
        let mut mock = MockTransport::new()
            .expect("/public-key", vec![MockLine::Timeout, MockLine::Disconnect]);
        mock.write_line("/public-key").unwrap();
        assert_eq!(mock.read_line(T).unwrap(), None);
        assert!(mock.read_line(T).is_err());
    }

    #[test]
    fn mock_failing_writes_mode() {
        let mut mock = MockTransport::new()
            .expect("/public-key", vec![])
            .with_failing_writes();
        assert!(mock.write_line("/public-key").is_err());
    }

    #[test]
    fn probe_ping_happy_with_noise() {
        let mut mock = MockTransport::new().expect_prefix(
            "/ping ",
            vec![
                MockLine::line("booting nsd firmware"),
                MockLine::line("/ping"), // unsolicited bare ping → skipped
                MockLine::line("/ping 0 dev-42"),
            ],
        );
        assert!(probe_ping(&mut mock, Duration::from_secs(1)));
    }

    #[test]
    fn probe_ping_timeout_and_write_failure() {
        let mut silent = MockTransport::new().expect_prefix("/ping ", vec![MockLine::Timeout]);
        assert!(!probe_ping(&mut silent, Duration::from_secs(1)));

        let mut dead = MockTransport::new().with_failing_writes();
        assert!(!probe_ping(&mut dead, Duration::from_secs(1)));
    }
}
