use std::{
    io,
    sync::{Mutex, MutexGuard},
};
use tracing_subscriber::fmt::MakeWriter;

lazy_static! {
    pub static ref GLOBAL_TRACING_BUF: Mutex<Vec<u8>> = Mutex::new(vec![]);
}

#[derive(Debug)]
pub struct TracingWriter<'a> {
    buf: &'a Mutex<Vec<u8>>,
}

impl<'a> TracingWriter<'a> {
    pub fn new(buf: &'a Mutex<Vec<u8>>) -> Self {
        Self { buf }
    }

    fn buf(&self) -> io::Result<MutexGuard<'a, Vec<u8>>> {
        self.buf
            .lock()
            .map_err(|_| io::Error::from(io::ErrorKind::Other))
    }
}

impl<'a> io::Write for TracingWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut target = self.buf()?;
        print!("{}", String::from_utf8(buf.to_vec()).unwrap());
        target.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.buf()?.flush()
    }
}

impl<'a> MakeWriter for TracingWriter<'a> {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        TracingWriter::new(self.buf)
    }
}

// logs_contain may panic so don't use in production code
pub fn logs_contain(s: &str) -> bool {
    let logs = String::from_utf8(GLOBAL_TRACING_BUF.lock().unwrap().to_vec()).unwrap();
    for line in logs.split('\n') {
        if line.contains(s) {
            return true;
        }
    }
    false
}

pub fn logs_clear() -> () {
    GLOBAL_TRACING_BUF.lock().unwrap().clear()
}
