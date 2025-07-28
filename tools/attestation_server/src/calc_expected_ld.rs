use serde::{Deserialize, Serialize};
use sev::firmware::guest::{GuestPolicy, PlatformInfo};
use sev::firmware::host::TcbVersion;
use sev::measurement::{
    snp::{snp_calc_launch_digest, SnpMeasurementArgs},
    vmsa::{GuestFeatures, VMMType},
    vcpu_types::CpuType,
};
use snafu::{whatever, ResultExt, Whatever};

use crate::snp_validate_report::ProductName;
use hex_buffer_serde::{Hex as _, HexForm};

///Length fo the FamilyID and the ImageID data types in bytes
pub const IDBLOCK_ID_BYTES :usize = 16;

#[derive(Serialize, Deserialize, Default)]
///User facing config struct to specify a VM.
///Used to compute the epxected launch measurment
pub struct VMDescription {
    pub host_cpu_family: ProductName,
    pub vcpu_count: u32,
    pub ovmf_file: String,
    /// Security relevant SEV configuration/kernel features. Defined in the VMSA of the VM. Thus they affect the computation of the expected launch measurement. See `SEV_FEATURES` in Table B-4 in https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf
    ///TODO: implement nice way to detect which features are used on a given system
    pub guest_features: GuestFeatures,
    pub kernel_file: String,
    pub initrd_file: String,
    pub kernel_cmdline: String,
    pub platform_info: PlatformInfo,
    ///Mininum required committed version numbers
    ///Committed means that the platform cannot be rolled back to a prior
    ///version
    pub min_commited_tcb: TcbVersion,
    /// Policy passed to QEMU and reflected in the attestation report
    pub guest_policy: GuestPolicy,
    #[serde(with = "HexForm")]
    pub family_id: [u8; IDBLOCK_ID_BYTES],
    #[serde(with = "HexForm")]
    pub image_id: [u8; IDBLOCK_ID_BYTES],
}
pub fn format_guest_features(features: &GuestFeatures) -> String {
    let mut enabled_features = Vec::new();

    if features.snp_active() {
        enabled_features.push("SNPActive");
    }
    if features.v_tom() {
        enabled_features.push("vTOM");
    }
    if features.reflect_vc() {
        enabled_features.push("ReflectVC");
    }
    if features.restricted_injection() {
        enabled_features.push("RestrictedInjection");
    }
    if features.alternate_injection() {
        enabled_features.push("AlternateInjection");
    }
    if features.debug_swap() {
        enabled_features.push("DebugSwap");
    }
    if features.prevent_host_ibs() {
        enabled_features.push("PreventHostIBS");
    }
    if features.btb_isolation() {
        enabled_features.push("BTBIsolation");
    }
    if features.vmpl_sss() {
        enabled_features.push("VmplSSS");
    }
    if features.secure_tsc() {
        enabled_features.push("SecureTSC");
    }
    if features.vmg_exit_parameter() {
        enabled_features.push("VmgexitParameter");
    }
    if features.ibs_virtualization() {
        enabled_features.push("IbsVirtualization");
    }
    if features.vmsa_reg_prot() {
        enabled_features.push("VmsaRegProt");
    }
    if features.smt_protection() {
        enabled_features.push("SmtProtection");
    }

    // Format the output string
    if enabled_features.is_empty() {
        "None".to_string()
    } else {
        enabled_features.join(", ")
    }
}

fn display_snp_measurement_args(snp_measure_args: &SnpMeasurementArgs<'_>) {
    println!("Computing expected launch digest based on:");
    println!("  vcpus:          {:?}", snp_measure_args.vcpus);
    println!("  vcpu_type:      {:?}", snp_measure_args.vcpu_type);
    println!("  ovmf_file:      {:?}", snp_measure_args.ovmf_file);
    println!("  guest_features: {}", format!("{:064b}", snp_measure_args.guest_features.0));
    println!("                  {:?}", format_guest_features(&snp_measure_args.guest_features));
    println!("  kernel_file:    {:?}", snp_measure_args.kernel_file.as_deref().and_then(|p| p.to_str()).unwrap_or(""));
    println!("  initrd_file:    {:?}", snp_measure_args.initrd_file.as_deref().and_then(|p| p.to_str()).unwrap_or(""));
    println!("  append:         {:?}", snp_measure_args.append.unwrap_or(""));
    println!("  ovmf_hash_str:  {:?}", snp_measure_args.ovmf_hash_str);
    println!("  vmm_type:       {:?}", snp_measure_args.vmm_type.map(|vmm| match vmm {
        VMMType::QEMU => "QEMU",
        VMMType::EC2 => "EC2",
        VMMType::KRUN => "KRUN",
    }).unwrap_or(""));
}

impl VMDescription {
    pub fn compute_expected_hash(&self) -> Result<[u8; 384 / 8], Whatever> {
        let snp_measure_args = SnpMeasurementArgs {
            vcpus: self.vcpu_count,
            vcpu_type: CpuType::EpycV4,
            ovmf_file: self.ovmf_file.clone().into(),
            guest_features: self.guest_features,
            kernel_file: Some(self.kernel_file.clone().into()),
            initrd_file: Some(self.initrd_file.clone().into()),
            append: if self.kernel_cmdline != "" {
                Some(&self.kernel_cmdline)
            } else {
                None
            },
            //if none, we calc ovmf hash based on ovmf file
            ovmf_hash_str: None,
            vmm_type: Some(VMMType::QEMU),
        };
        display_snp_measurement_args(&snp_measure_args);

        let ld = snp_calc_launch_digest(snp_measure_args)
            .whatever_context("failed to compute launch digest")?;
        let ld_vec = bincode::serialize(&ld).whatever_context("failed to bincode serialized SnpLaunchDigest to Vec<u8>")?;
        let ld_arr : [u8; 384 / 8] = match ld_vec.try_into() {
            Ok(v) => v,
            Err(_) => whatever!("SnpLaunchDigest has unexpected length"),
        };
        Ok(ld_arr)
    }
}

#[cfg(test)]
mod test {
    use std::fs;

    use super::VMDescription;

    #[test]
    fn parse_toml() {
        println!(
            "Expected\n\n{}",
            toml::to_string_pretty(&VMDescription::default()).unwrap()
        );
        let _conf: VMDescription =
            toml::from_str(&fs::read_to_string("./examples/vm-config.toml").unwrap()).unwrap();
    }
}
