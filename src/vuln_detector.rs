use crate::feature_extractor::CodeFeatures;

#[derive(Debug)]
pub struct SecurityReport {
    pub confidence: f32,
    pub vulnerabilities: Vec<String>,
}

pub fn detect_vulnerabilities(features: &CodeFeatures) -> SecurityReport {
    let mut vulns = Vec::new();
    
    if features.unsafe_blocks > 0 {
        vulns.push("Unsafe block detected".into());
    }
    if features.path_traversal {
        vulns.push("Potential path traversal".into());
    }
    if features.command_injection {
        vulns.push("Potential command injection".into());
    }
    if features.double_free_risk {
        vulns.push("Potential double-free in unsafe block".into());
    }
    if features.dangling_references {
        vulns.push("Dangling reference in unsafe code".into());
    }
    if features.data_race_risk {
        vulns.push("Possible data race (shared mutable state)".into());
    }
    if features.insecure_crypto {
        vulns.push("Use of insecure cryptographic algorithm".into());
    }
    if features.unchecked_unwrap {
        vulns.push("Unchecked unwrap/expect usage".into());
    }
    if features.deprecated_functions {
        vulns.push("Use of deprecated functions".into());
    }
    
    SecurityReport {
        confidence: if !vulns.is_empty() { 0.9 } else { 0.1 },
        vulnerabilities: vulns,
    }
}