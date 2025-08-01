mod sniffer;
use pyo3::prelude::*;
use sniffer::Sniffer;

#[pymodule]
fn net_sentry(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Sniffer>()?;
    Ok(())
}
