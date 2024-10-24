use clap::Parser;
use serde::Deserialize;

use crate::realm::RealmError;
use crate::utils::*;

type Result<T> = core::result::Result<T, RealmError>;

fn check_ipa_bits(v: u8) -> Result<u8> {
    Ok(v)
}

fn check_num_bps(v: u8) -> Result<u8> {
    if v < 2 || v > 64 {
        return Err(RealmError::Parameter(format!("breakpoints '{v}'")));
    }
    Ok(v)
}

fn check_num_wps(v: u8) -> Result<u8> {
    if v < 2 || v > 64 {
        return Err(RealmError::Parameter(format!("watchpoints '{v}'")));
    }
    Ok(v)
}

fn check_pmu_ctrs(v: u8) -> Result<u8> {
    if v > 31 {
        return Err(RealmError::Parameter(format!("PMU counters '{v}'")));
    }
    Ok(v)
}

fn check_sve_vl(v: u16) -> Result<u16> {
    if v != 0 && !sve_vl_is_valid(v) {
        return Err(RealmError::Parameter(format!("SVE vector length '{v}'")));
    }
    Ok(v)
}

// Update @old in place if @new is lower than @old, or if @old was None
fn restrict_val<T: Copy + std::cmp::PartialOrd>(old: &mut Option<T>, new: T) {
    let old_val = old.unwrap_or(new);
    if new <= old_val {
        *old = Some(new);
    }
}

/// Host capabilities influence the VM configuration. They contain hardware
/// capabilities, restricted by both the non-secure and the Realm hypervisor.
/// For example, if HW and KVM support 10 PMU counters but RMM doesn't then
/// pmu_num_ctrs is 0.
#[derive(Debug, Parser, Default, Deserialize)]
#[command(next_help_heading = "Host capabilities")]
#[serde(deny_unknown_fields)]
pub struct RealmParams {
    /// Number of IPA bits
    #[arg(long, value_name = "N")]
    pub ipa_bits: Option<u8>,

    /// Maximum number of breakpoints (2-16)
    #[arg(long, value_name = "N")]
    pub num_bps: Option<u8>,

    /// Maximum number of watchpoints (2-16)
    #[arg(long, value_name = "N")]
    pub num_wps: Option<u8>,

    /// Maximum SVE vector length (bits, pow of two, 128-2048, 0 disables)
    #[arg(long, value_name = "N")]
    pub sve_vl: Option<u16>,

    /// Maximum number of PMU counters (0-31)
    #[arg(long, value_name = "N")]
    pub pmu_num_ctrs: Option<u8>,

    /// PMU is supported
    #[arg(long)]
    pub pmu: Option<bool>,

    /// LPA2 is supported
    #[arg(long)]
    pub lpa2: Option<bool>,

    /// Hash algorithm
    #[arg(long)]
    pub hash_algo: Option<rmm::RmiHashAlgorithm>,
}

impl RealmParams {
    /// Set the number of IPA bits.
    pub fn set_ipa_bits(&mut self, v: u8) -> Result<()> {
        self.ipa_bits = Some(check_ipa_bits(v)?);
        Ok(())
    }

    /// Set the number of IPA bits if `v` is smaller than the current parameter.
    pub fn restrict_ipa_bits(&mut self, v: u8) -> Result<()> {
        restrict_val(&mut self.ipa_bits, check_ipa_bits(v)?);
        Ok(())
    }

    /// Set the number of breakpoints.
    pub fn set_num_bps(&mut self, v: u8) -> Result<()> {
        self.num_bps = Some(check_num_bps(v)?);
        Ok(())
    }

    /// Set the number of breakpoints if `v` is smaller than the current
    /// parameter.
    pub fn restrict_num_bps(&mut self, v: u8) -> Result<()> {
        restrict_val(&mut self.num_bps, check_num_bps(v)?);
        Ok(())
    }

    /// Set the number of watchpoints.
    pub fn set_num_wps(&mut self, v: u8) -> Result<()> {
        self.num_wps = Some(check_num_wps(v)?);
        Ok(())
    }

    /// Set the number of watchpoints if `v` is smaller than the current
    /// parameter.
    pub fn restrict_num_wps(&mut self, v: u8) -> Result<()> {
        restrict_val(&mut self.num_wps, check_num_wps(v)?);
        Ok(())
    }

    /// Enable or disable the PMU
    pub fn set_pmu(&mut self, pmu: bool) {
        self.pmu = Some(pmu);
    }

    /// Disable the PMU, or enable it if not already disabled.
    pub fn restrict_pmu(&mut self, pmu: bool) {
        restrict_val(&mut self.pmu, pmu);
    }

    /// Set the number of PMU counters.
    pub fn set_pmu_num_ctrs(&mut self, num_ctrs: u8) -> Result<()> {
        self.pmu_num_ctrs = Some(check_pmu_ctrs(num_ctrs)?);
        Ok(())
    }

    /// Set the number of PMU counters if `v` is smaller than the current
    /// parameter.
    pub fn restrict_pmu_num_ctrs(&mut self, v: u8) -> Result<()> {
        restrict_val(&mut self.pmu_num_ctrs, check_pmu_ctrs(v)?);
        Ok(())
    }

    /// Set SVE vector length in bits.
    pub fn set_sve_vl(&mut self, v: u16) -> Result<()> {
        self.sve_vl = Some(check_sve_vl(v)?);
        Ok(())
    }

    /// Set SVE vector length in bits if `v` is lower than the current
    /// parameter.
    pub fn restrict_sve_vl(&mut self, v: u16) -> Result<()> {
        restrict_val(&mut self.sve_vl, check_sve_vl(v)?);
        Ok(())
    }

    /// Enable or disable LPA2.
    pub fn set_lpa2(&mut self, lpa2: bool) {
        self.lpa2 = Some(lpa2);
    }

    /// Disable LPA2, or enable it if not already disabled.
    pub fn restrict_lpa2(&mut self, lpa2: bool) {
        restrict_val(&mut self.lpa2, lpa2);
    }

    /// Update our paramaters with the given configuration. Throw an error for
    /// any invalid value.
    pub fn udpate(&mut self, other: &RealmParams) -> Result<()> {
        if let Some(v) = other.ipa_bits {
            self.set_ipa_bits(v)?;
        }
        if let Some(v) = other.num_bps {
            self.set_num_bps(v)?;
        }
        if let Some(v) = other.num_wps {
            self.set_num_wps(v)?;
        }
        if let Some(v) = other.pmu_num_ctrs {
            self.set_pmu_num_ctrs(v)?;
        }
        if let Some(v) = other.sve_vl {
            self.set_sve_vl(v)?;
        }
        if let Some(v) = other.pmu {
            self.set_pmu(v);
        }
        if let Some(v) = other.lpa2 {
            self.set_lpa2(v);
        }
        Ok(())
    }

    /// Restrict our parameters using the given configuration. Only update
    /// values if they are smaller. Throw an error for any invalid value.
    pub fn restrict(&mut self, other: &RealmParams) -> Result<()> {
        if let Some(v) = other.ipa_bits {
            self.restrict_ipa_bits(v)?;
        }
        if let Some(v) = other.num_bps {
            self.restrict_num_bps(v)?;
        }
        if let Some(v) = other.num_wps {
            self.restrict_num_wps(v)?;
        }
        if let Some(v) = other.pmu_num_ctrs {
            self.restrict_pmu_num_ctrs(v)?;
        }
        if let Some(v) = other.sve_vl {
            self.restrict_sve_vl(v)?;
        }
        if let Some(v) = other.pmu {
            self.restrict_pmu(v);
        }
        if let Some(v) = other.lpa2 {
            self.restrict_lpa2(v);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Test setters that check the values
    fn test_args() {
        let mut p = RealmParams::default();

        assert!(p.set_sve_vl(272).is_err());
        assert!(p.set_sve_vl(4096).is_err());
        assert!(p.sve_vl.is_none());
        assert!(p.set_sve_vl(128).is_ok());
        assert_eq!(p.sve_vl, Some(128));
        assert_eq!(sve_vl_to_vq(128), 0);
        assert!(p.set_sve_vl(2048).is_ok());
        assert_eq!(p.sve_vl, Some(2048));
        assert_eq!(sve_vl_to_vq(2048), 15);
        assert!(p.set_sve_vl(0).is_ok());
        assert_eq!(p.sve_vl, Some(0));

        assert!(p.set_num_bps(1).is_err());
        assert!(p.set_num_bps(65).is_err());
        assert!(p.set_num_bps(2).is_ok());
        assert_eq!(p.num_bps, Some(2));
        assert!(p.set_num_bps(16).is_ok());
        assert_eq!(p.num_bps, Some(16));

        assert!(p.set_num_wps(1).is_err());
        assert!(p.set_num_wps(65).is_err());
        assert!(p.set_num_wps(2).is_ok());
        assert_eq!(p.num_wps, Some(2));
        assert!(p.set_num_wps(16).is_ok());
        assert_eq!(p.num_wps, Some(16));

        assert_eq!(p.pmu_num_ctrs, None);
        assert!(p.set_pmu_num_ctrs(32).is_err());
        assert!(p.set_pmu_num_ctrs(0).is_ok());
        assert_eq!(p.pmu_num_ctrs, Some(0));
        assert!(p.set_pmu_num_ctrs(31).is_ok());
        assert_eq!(p.pmu_num_ctrs, Some(31));

        assert!(p.set_ipa_bits(48).is_ok());
        assert_eq!(p.ipa_bits, Some(48));
    }
}
