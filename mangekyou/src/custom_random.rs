#[cfg(all(target_arch = "bpf", not(test)))]
use getrandom::Error;

#[cfg(all(target_arch = "bpf", not(test)))]
#[no_mangle]
pub fn getrandom(buf: &mut [u8]) -> Result<(), Error> {
    // Simple deterministic pattern for verification purposes
    // This is safe because we're only using this for VRF verification, not generation
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    Ok(())
} 