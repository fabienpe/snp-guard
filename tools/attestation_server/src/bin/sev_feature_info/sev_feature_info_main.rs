//! Helper that show information about the sev config on the host system

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::env; // Import the env module for command-line arguments
use sev::firmware::host::Firmware;
use snafu::{ResultExt, Whatever};


// SEV status MSR is defined in /AMDSEV/linux/guest/arch/x86/include/asm/msr-index.h
const MSR_AMD64_SEV: u32 = 0xC0010131;
const MSR_SIZE: usize = 8; // MSRs are 64-bit (8 bytes)

// Reads a 64-bit MSR value for a specific CPU core.
//
// # Arguments
// * `cpu_id` - The ID of the CPU core (e.g., 0 for /dev/cpu/0/msr).
// * `msr_index` - The 32-bit index of the MSR to read.
//
// # Returns
// A `Result` containing the 64-bit MSR value on success, or an `io::Error` on failure.
fn read_msr_value(cpu_id: u32, msr_index: u32) -> io::Result<u64> {
    let path = PathBuf::from(format!("/dev/cpu/{}/msr", cpu_id));

    let mut file = File::open(&path)?;

    // Seek to the MSR index (offset within the msr device file)
    file.seek(SeekFrom::Start(msr_index as u64))?;

    // Read 8 bytes (64 bits)
    let mut buffer = [0u8; MSR_SIZE];
    file.read_exact(&mut buffer)?;

    // Convert the 8 bytes to a u64
    let msr_value = u64::from_le_bytes(buffer);

    Ok(msr_value)
}

fn main() -> Result<(), Whatever> {
    let mut firmware: Firmware = Firmware::open().whatever_context("failed to talk to HW")?;

    let platform_status = firmware
        .snp_platform_status()
        .whatever_context("error getting platform status")?;

    println!("{:#?}", platform_status);

    println!("--- Reading MSR 0x{:x} (MSR_AMD64_SEV) ---", MSR_AMD64_SEV);
    println!("(Requires 'msr' kernel module to be loaded and appropriate permissions for /dev/cpu/*/msr)");

    // Get command-line arguments
    let args: Vec<String> = env::args().collect();

    // There could be multiple CPU cores. MSRs are per-core.
    // We just check core 0. Could iterate through them all.
    let cpu_id: u32 = if args.len() > 1 {
        match args[1].parse() {
            Ok(id) => id,
            Err(_) => {
                eprintln!("Error: Invalid CPU ID provided. Please provide a non-negative integer.");
                eprintln!("Usage: {} <cpu_id>", args[0]);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("Error: CPU ID not provided.");
        eprintln!("Usage: {} <cpu_id>", args[0]);
        std::process::exit(1);
    };

    match read_msr_value(cpu_id, MSR_AMD64_SEV) {
        Ok(sev_status_value) => {
            println!("\nSuccessfully read MSR 0x{:x} on CPU {}: 0x{:x}", MSR_AMD64_SEV, cpu_id, sev_status_value);
            println!("  SEV_STATUS: 0x{:x}", sev_status_value);

            // Calculate SEV_FEATURES by right shifting sev_status_value by 2 bits
            // See: AMDSEV/ovmf/UefiCpuPkg/Library/MpInitLib/X64/AmdSev.c
            let sev_feature_value = sev_status_value >> 2;
            println!("  Derived SEV_FEATURES (SEV_STATUS >> 2): 0x{:x}", sev_feature_value);
        },
        Err(e) => {
            eprintln!("\nError reading MSR 0x{:x} on CPU {}: {}", MSR_AMD64_SEV, cpu_id, e);
            eprintln!("Possible reasons:");
            eprintln!("  1. The 'msr' kernel module is not loaded. Run 'sudo modprobe msr'.");
            eprintln!("  2. You need 'sudo' to run this program.");
            eprintln!("  3. The MSR index 0x{:x} might not be valid or accessible on your specific CPU.", MSR_AMD64_SEV);
            eprintln!("  4. The cpu_id ({}) may not exist.", cpu_id);
        },
    }

    Ok(())
}
