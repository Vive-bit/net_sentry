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
    #[staticmethod]
    pub fn list_devices() -> PyResult<Vec<String>> {
        let devices = Device::list()
            .map_err(|e| PyRuntimeError::new_err(format!("pcap Device list failed: {}", e)))?;
        Ok(devices.into_iter().map(|d| d.name).collect())
    }

    #[new]
    pub fn new(interface: &str, filter: Option<&str>) -> PyResult<Self> {
        let devices = Device::list()
            .map_err(|e| PyRuntimeError::new_err(format!("pcap Device list failed: {}", e)))?;

        let dev = devices
            .into_iter()
            .find(|d| d.name == interface)
            .ok_or_else(|| PyRuntimeError::new_err(format!("pcap: no such device '{}'", interface)))?;

        let mut cap = Capture::from_device(dev)
            .map_err(|e| PyRuntimeError::new_err(format!("pcap from_device failed: {}", e)))?
            .promisc(true)
            .immediate_mode(true)
            .timeout(1000)
            .open()
            .map_err(|e| PyRuntimeError::new_err(format!("pcap open failed: {}", e)))?;

        if let Some(expr) = filter {
            cap.filter(expr, true)
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
                Err(pcap::Error::TimeoutExpired) => break,
                Err(e) => {
                    return Err(PyRuntimeError::new_err(format!("pcap next() failed: {}", e)))
                }
            }
        }
        Ok(out)
    }
}
