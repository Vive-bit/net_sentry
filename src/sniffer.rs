use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyRuntimeError;
use pcap::{Capture, Device, Active};

#[pyclass]
pub struct Sniffer {
    cap: Capture<Active>,
}

#[pymethods]
impl Sniffer {
    #[new]
    pub fn new(interface: &str, filter: Option<&str>) -> PyResult<Self> {
        let devices = Device::list()
            .map_err(|e| PyRuntimeError::new_err(format!("pcap Device list failed: {}", e)))?;
        let dev = devices
            .into_iter()
            .find(|d| d.name == interface)
            .unwrap_or_else(|| Device::lookup().unwrap());
        let mut cap = Capture::from_device(dev)
            .map_err(|e| PyRuntimeError::new_err(format!("pcap from_device failed: {}", e)))?
            .promisc(true)
            .immediate_mode(true)
            .timeout(1000)
            .open()
            .map_err(|e| PyRuntimeError::new_err(format!("pcap open failed: {}", e)))?;
        if let Some(f) = filter {
            cap.filter(f, true)
                .map_err(|e| PyRuntimeError::new_err(format!("pcap filter failed: {}", e)))?;
        }
        Ok(Sniffer { cap })
    }

    pub fn next_batch(&mut self, batch_size: usize, py: Python) -> PyResult<Vec<PyObject>> {
        let mut out = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            match self.cap.next() {
                Ok(pkt) => {
                    let b = PyBytes::new(py, pkt.data).into_py(py);
                    out.push(b);
                }
                Err(e) => match e {
                    pcap::Error::TimeoutExpired => break,
                    _ => {
                        return Err(PyRuntimeError::new_err(format!("pcap next() failed: {}", e)))
                    }
                },
            }
        }
        Ok(out)
    }
}
