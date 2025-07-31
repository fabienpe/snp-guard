use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;

use clap::Parser;
use sev::firmware::guest::{AttestationReport, Firmware};
use snafu::{whatever, ResultExt, Whatever};
use base64::{engine::general_purpose, Engine};
use anyhow::Result;
use serde_json::json;


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

#[derive(Parser, Debug)]
struct Args {
    /// Path to output file
    #[arg(long, default_value = "attestation_report.json")]
    out: String,

    /// Path to binary output file (can be used with snp-guest tool)
    #[arg(long, default_value = "attestation_report.bin")]
    out_bin: String,

    /// Optional 64-byte data to pass to the report, encoded in base64
    #[arg(long, default_value = "")]
    report_data: String,

    /// Optional integer ID of the CPU core to read SEV_STATUS from
    /// There could be multiple CPU cores. MSRs are per-core.
    #[arg(long, default_value = "0")]
    cpu_id: u32,

    /// Path to binary output file (can be used with snpguest tool)
    #[arg(long, default_value = "sev_feature.json")]
    out_sev: String,
}
#[snafu::report]
fn main() -> Result<(), Whatever> {
    let args = Args::parse();

    let report_data_raw = general_purpose::STANDARD_NO_PAD
        .decode(&args.report_data)
        .whatever_context("failed to decode report_data as base64")?;
    let len = report_data_raw.len();

    if len > 64 {
        whatever!("report data length should be <= 64 bytes, but got {} bytes!", len);
    }

    let mut report_data = [0u8; 64];
    report_data[..len].copy_from_slice(&report_data_raw);
    
    let mut fw = Firmware::open().whatever_context("failed to open sev firmware device. Is this a SEV-SNP guest?")?;
    let report = fw.get_report(None, Some(report_data), None).whatever_context("error getting report from firmware device")?;
    let attestation = AttestationReport::from_bytes(report.as_slice())
        .whatever_context("failed to build attestation report object from bytes")?;
    
    println!("Reading MSR 0x{:x} (MSR_AMD64_SEV) ---", MSR_AMD64_SEV);
    match read_msr_value(args.cpu_id, MSR_AMD64_SEV) {
        Ok(sev_status_value) => {
            println!("\nSuccessfully read MSR 0x{:x} on CPU {}: 0x{:x}", MSR_AMD64_SEV, args.cpu_id, sev_status_value);
            println!("  SEV_STATUS: 0x{:x}", sev_status_value);

            // Calculate SEV_FEATURES by right shifting sev_status_value by 2 bits
            // See: AMDSEV/ovmf/UefiCpuPkg/Library/MpInitLib/X64/AmdSev.c
            let sev_feature_value = sev_status_value >> 2;
            println!("  Derived SEV_FEATURES (SEV_STATUS >> 2): 0x{:x}", sev_feature_value);

            let sev_feature_json = json!({ 
                "sev_status": sev_status_value,
                "sev_feature": sev_feature_value });
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&args.out_sev)
                .whatever_context("failed to create SEV feature file report")?;
             serde_json::to_writer(&mut file, &sev_feature_json).whatever_context("failed to write to file")?;
             println!("SEV feature saved in {}", &args.out_sev);
        },
        Err(e) => {
            eprintln!("\nError reading MSR 0x{:x} on CPU {}: {}", MSR_AMD64_SEV, args.cpu_id, e);
            eprintln!("Possible reasons:");
            eprintln!("  1. The 'msr' kernel module is not loaded. Run 'sudo modprobe msr'.");
            eprintln!("  2. You need 'sudo' to run this program.");
            eprintln!("  3. The MSR index 0x{:x} might not be valid or accessible on your specific CPU.", MSR_AMD64_SEV);
            eprintln!("  4. The cpu_id ({}) may not exist.", args.cpu_id);
        },
    }

    // Save attestation as JSON
    let f = File::create(&args.out).whatever_context(format!("failed to create output file {}",&args.out))?;
    println!("Your result is at {}.\nCopy it to the host system and the \"verify_report\" binary to verify it, as described in the README", &args.out);
    serde_json::to_writer(f, &attestation).whatever_context("failed to serialize report as json")?;
    
    // Also save the report as binary so it can be usd by snpguest tool
    // See https://github.com/virtee/snpguest/blob/main/src/report.rs
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&args.out_bin).whatever_context("failed to create file for binary report")?;
    attestation.write_bytes(&mut file)
    .whatever_context("failed to write binary attestation report")?;
    
    Ok(())
}