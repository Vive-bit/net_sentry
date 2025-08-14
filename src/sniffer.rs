use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyRuntimeError;
use pcap::{Capture, Device, Active};
use pcap::Stat;

#[pyclass]
pub struct Sniffer {
    cap: Capture<Active>,
}

#[pymethods]
impl Sniffer {
    #[staticmethod]
    pub fn list_devices() -> PyResult<Vec<String>> {
        let devices = Device::list()
            .map_err(|e| PyRuntimeError::new_err(format!("pcap Device list failed: {}", e)))?;
        Ok(devices.into_iter().map(|d| d.name).collect())
    }

    #[new]
    pub fn new(interface: &str, filter: Option<&str>) -> PyResult<Self> {
        let dev = Device::list()
            .map_err(|e| PyRuntimeError::new_err(format!("Device list failed: {}", e)))?
            .into_iter()
            .find(|d| d.name == interface)
            .ok_or_else(|| PyRuntimeError::new_err(format!("no such device '{}'", interface)))?;

        let mut cap = Capture::from_device(dev)
            .map_err(|e| PyRuntimeError::new_err(format!("from_device failed: {}", e)))?
            .promisc(true)
            .immediate_mode(true)
            .timeout(1000)
            .snaplen(262_144)
            .buffer_size(4 * 1024 * 1024)
            .open()
            .map_err(|e| PyRuntimeError::new_err(format!("open failed: {}", e)))?;

        if let Some(expr) = filter {
            cap.filter(expr, true)
                .map_err(|e| PyRuntimeError::new_err(format!("filter failed: {}", e)))?;
        }

        Ok(Sniffer { cap })
    }

    pub fn stats(&mut self) -> PyResult<(u32,u32,u32)> {
        match self.cap.stats() {
            Ok(Stat { received, dropped, if_dropped }) => Ok((received, dropped, if_dropped)),
            Err(e) => Err(PyRuntimeError::new_err(format!("stats failed: {}", e))),
        }
    }

    pub fn set_filter(&mut self, expr: &str) -> PyResult<()> {
        self.cap
            .filter(expr, true)
            .map_err(|e| PyRuntimeError::new_err(format!("filter failed: {}", e)))
    }

    pub fn set_nonblock(&mut self, nonblock: bool) -> PyResult<()> {
        self.cap
            .setnonblock(nonblock)
            .map_err(|e| PyRuntimeError::new_err(format!("setnonblock failed: {}", e)))
    }

    pub fn set_timeout(&mut self, ms: i32) -> PyResult<()> {
        self.cap
            .set_timeout(ms)
            .map_err(|e| PyRuntimeError::new_err(format!("set_timeout failed: {}", e)))
    }

 //   pub fn next_batch(&mut self, batch_size: usize, py: Python) -> PyResult<Vec<PyObject>> {
 //       let mut out = Vec::with_capacity(batch_size);
 //       for _ in 0..batch_size {
 //           match self.cap.next() {
 //               Ok(pkt) => {
 //                   let b = PyBytes::new(py, pkt.data).into_py(py);
 //                   out.push(b);
 //               }
 //               Err(pcap::Error::TimeoutExpired) => break,
 //               Err(e) => {
 //                   return Err(PyRuntimeError::new_err(format!("pcap next() failed: {}", e)))
 //               }
 //           }
 //       }
 //       Ok(out)
 //   }

 //   pub fn next_batch_meta(&mut self, batch_size: usize, py: Python) -> PyResult<Vec<PyObject>> {
 //       let mut out = Vec::with_capacity(batch_size);
 //       for _ in 0..batch_size {
 //           match self.cap.next() {
 //               Ok(pkt) => {
 //                   let b = PyBytes::new(py, pkt.data).into_py(py);
 //                   let ts = (pkt.header.ts.tv_sec, pkt.header.ts.tv_usec);
 //                   let caplen = pkt.header.caplen as usize;
 //                   let origlen = pkt.header.len as usize;
 //                   out.push((ts.0, ts.1, caplen, origlen, b).into_py(py));
 //               }
 //               Err(pcap::Error::TimeoutExpired) => break,
 //               Err(e) => return Err(PyRuntimeError::new_err(format!("pcap next() failed: {}", e))),
 //           }
 //       }
 //       Ok(out)
 //   }

    pub fn next_batch(&mut self, batch_size: usize, py: Python) -> PyResult<Vec<PyObject>> {
        let packets: Result<Vec<Vec<u8>>, pcap::Error> = py.allow_threads(|| {
            let mut v = Vec::with_capacity(batch_size);
            for _ in 0..batch_size {
                match self.cap.next() {
                    Ok(pkt) => v.push(pkt.data.to_vec()), 
                    Err(pcap::Error::TimeoutExpired) => break,
                    Err(e) => return Err(e),
                }
            }
            Ok(v)
        });
    
        let packets = packets.map_err(|e| PyRuntimeError::new_err(format!("pcap next() failed: {}", e)))?;
    
        let mut out: Vec<PyObject> = Vec::with_capacity(packets.len());
        for buf in packets {
            out.push(PyBytes::new(py, &buf).into_py(py));
        }
        Ok(out)
    }

    
    pub fn next_batch_meta(&mut self, batch_size: usize, py: Python) -> PyResult<Vec<PyObject>> {
        let items: Result<Vec<((i64,i64), usize, usize, Vec<u8>)>, pcap::Error> = py.allow_threads(|| {
            let mut v = Vec::with_capacity(batch_size);
            for _ in 0..batch_size {
                match self.cap.next() {
                    Ok(pkt) => {
                        let ts = (pkt.header.ts.tv_sec as i64, pkt.header.ts.tv_usec as i64);
                        let caplen = pkt.header.caplen as usize;
                        let origlen = pkt.header.len as usize;
                        v.push((ts, caplen, origlen, pkt.data.to_vec()));
                    }
                    Err(pcap::Error::TimeoutExpired) => break,
                    Err(e) => return Err(e),
                }
            }
            Ok(v)
        });
    
        let items = items.map_err(|e| PyRuntimeError::new_err(format!("pcap next() failed: {}", e)))?;
    
        let mut out: Vec<PyObject> = Vec::with_capacity(items.len());
        for ((sec,usec), caplen, origlen, buf) in items {
            let pybytes = PyBytes::new(py, &buf).into_py(py);
            out.push((sec, usec, caplen, origlen, pybytes).into_py(py));
        }
        Ok(out)
    }
}
