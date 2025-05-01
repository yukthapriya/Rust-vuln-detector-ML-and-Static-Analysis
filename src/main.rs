mod data_loader;
mod ml;
mod static_analysis;
mod feature_extractor;
mod vuln_detector;
mod vulnerability_detectors;

use anyhow::Result;
use csv::Writer;
use walkdir::WalkDir;
use crate::static_analysis::{analyze_file, CodeAnalysis};
use crate::ml::train_model;
use crate::feature_extractor::extract_features;
use crate::vuln_detector::detect_vulnerabilities;

const VULN_REPORT: &str = "security_report.csv";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read and analyze the main.rs file itself as an example
    let code = std::fs::read_to_string("src/main.rs")?;
    let features = extract_features(&code);
    let report = detect_vulnerabilities(&features);
    
    // Analyze the entire codebase
    let analyses = analyze_codebase("src")?;
    
    // Print immediate results
    println!("Unsafe Probability: {:.2}%", report.confidence * 100.0);
    for vuln in &report.vulnerabilities {
        println!("- {}", vuln);
    }

    // Generate CSV report
    generate_security_report(&analyses)?;
    
    // Train ML model
    let _model = train_model()?;
    
    Ok(())
}

fn analyze_codebase(dir_path: &str) -> Result<Vec<CodeAnalysis>> {
    let mut analyses = Vec::new();
    for entry in WalkDir::new(dir_path) {
        let entry = entry?;
        if entry.file_type().is_file() && entry.path().extension().map_or(false, |e| e == "rs") {
            match analyze_file(entry.path()) {
                Ok(analysis) => analyses.push(analysis),
                Err(e) => eprintln!("Error analyzing {}: {}", entry.path().display(), e),
            }
        }
    }
    Ok(analyses)
}

fn generate_security_report(analyses: &[CodeAnalysis]) -> Result<()> {
    let mut wtr = Writer::from_path(VULN_REPORT)?;
    
    wtr.write_record(&[
        "file_path", "buffer_overflow", "sql_injection", "xss", "command_injection",
        "path_traversal", "memory_leak", "integer_overflow", "race_condition",
        "use_after_free", "null_ptr_deref", "uninit_memory", "double_free",
        "format_string", "insecure_crypto", "insecure_deserialization",
        "improper_error_handling", "incorrect_lifetime", "unsafe_ffi",
        "type_confusion", "side_channel", "dos", "improper_input_validation",
        "insecure_randomness", "hardcoded_secrets", "logging_sensitive_info",
        "insecure_dependency", "improper_privileges", "business_logic_flaw",
        "unvalidated_recursion", "unbounded_allocation", "unsafe_blocks", "code_snippet"
    ])?;

    for analysis in analyses {
        wtr.write_record(&[
            analysis.file_path.display().to_string(),
            analysis.buffer_overflow.to_string(),
            analysis.sql_injection.to_string(),
            analysis.xss.to_string(),
            analysis.command_injection.to_string(),
            analysis.path_traversal.to_string(),
            analysis.memory_leak.to_string(),
            analysis.integer_overflow.to_string(),
            analysis.race_condition.to_string(),
            analysis.use_after_free.to_string(),
            analysis.null_ptr_deref.to_string(),
            analysis.uninit_memory.to_string(),
            analysis.double_free.to_string(),
            analysis.format_string.to_string(),
            analysis.insecure_crypto.to_string(),
            analysis.insecure_deserialization.to_string(),
            analysis.improper_error_handling.to_string(),
            analysis.incorrect_lifetime.to_string(),
            analysis.unsafe_ffi.to_string(),
            analysis.type_confusion.to_string(),
            analysis.side_channel.to_string(),
            analysis.dos.to_string(),
            analysis.improper_input_validation.to_string(),
            analysis.insecure_randomness.to_string(),
            analysis.hardcoded_secrets.to_string(),
            analysis.logging_sensitive_info.to_string(),
            analysis.insecure_dependency.to_string(),
            analysis.improper_privileges.to_string(),
            analysis.business_logic_flaw.to_string(),
            analysis.unvalidated_recursion.to_string(),
            analysis.unbounded_allocation.to_string(),
            analysis.unsafe_blocks.to_string(),
            analysis.code_snippet.clone(),
        ])?;
    }

    wtr.flush()?;
    println!("Security report generated: {}", VULN_REPORT);
    Ok(())
}