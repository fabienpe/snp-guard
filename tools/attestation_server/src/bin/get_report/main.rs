use std::fs::{File, OpenOptions};

use clap::Parser;
use sev::firmware::guest::{AttestationReport, Firmware};
use snafu::{whatever, ResultExt, Whatever};
use base64::{engine::general_purpose, Engine};
use anyhow::Result;

#[derive(Parser, Debug)]
struct Args {
    /// Path to output file
    #[arg(long, default_value = "attestation_report.json")]
    out: String,

    /// Optional 64-byte data to pass to the report, encoded in base64
    #[arg(long, default_value = "")]
    report_data: String,
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
    
    // Save attestation as JSON
    let f = File::create(&args.out).whatever_context(format!("failed to create output file {}",&args.out))?;
    println!("Your result is at {}.\nCopy it to the host system and the \"verify_report\" binary to verify it, as described in the README", &args.out);
    serde_json::to_writer(f, &attestation).whatever_context("failed to serialize report as json")?;
    
    // Also save the report as binary
    // See https://github.com/virtee/snpguest/blob/main/src/report.rs
    let bin_filename = &args.out.replace(".json", ".bin");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(bin_filename).whatever_context("failed to create file for binary report")?;
    attestation.write_bytes(&mut file)
    .whatever_context("failed to write binary attestation report")?;
    
    Ok(())
}