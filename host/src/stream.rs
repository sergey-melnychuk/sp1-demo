use std::io::{self, Read, Write};
use std::net::TcpStream;

/// Wraps a `TcpStream` and records every raw byte in both directions.
///
/// `inbound`  — bytes received from the server (server → client TLS records)
/// `outbound` — bytes sent to the server   (client → server TLS records)
pub struct CapturingStream {
    inner: TcpStream,
    pub inbound: Vec<u8>,
    pub outbound: Vec<u8>,
}

impl CapturingStream {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            inner: stream,
            inbound: Vec::new(),
            outbound: Vec::new(),
        }
    }
}

impl Read for CapturingStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.inbound.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl Write for CapturingStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.outbound.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
