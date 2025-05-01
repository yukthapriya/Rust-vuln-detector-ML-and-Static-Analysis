use std::fs;
use std::path::{Path, PathBuf};
use syn::{parse_file, visit::Visit};
use regex::Regex;
use anyhow::Result;

#[derive(Debug, Default)]
pub struct CodeAnalysis {
    pub buffer_overflow: bool,
    pub sql_injection: bool,
    pub xss: bool,
    pub command_injection: bool,
    pub path_traversal: bool,
    pub memory_leak: bool,
    pub integer_overflow: bool,
    pub race_condition: bool,
    pub use_after_free: bool,
    pub null_ptr_deref: bool,
    pub uninit_memory: bool,
    pub double_free: bool,
    pub format_string: bool,
    pub insecure_crypto: bool,
    pub insecure_deserialization: bool,
    pub improper_error_handling: bool,
    pub incorrect_lifetime: bool,
    pub unsafe_ffi: bool,
    pub type_confusion: bool,
    pub side_channel: bool,
    pub dos: bool,
    pub improper_input_validation: bool,
    pub insecure_randomness: bool,
    pub hardcoded_secrets: bool,
    pub logging_sensitive_info: bool,
    pub insecure_dependency: bool,
    pub improper_privileges: bool,
    pub business_logic_flaw: bool,
    pub unvalidated_recursion: bool,
    pub unbounded_allocation: bool,
    pub unsafe_blocks: usize,
    pub code_snippet: String,
    pub file_path: PathBuf,
}

impl CodeAnalysis {
    pub fn new(file_path: PathBuf, code: String) -> Self {
        Self {
            file_path,
            code_snippet: code,
            ..Default::default()
        }
    }
}

pub fn analyze_file(file_path: &Path) -> Result<CodeAnalysis> {
    let code = fs::read_to_string(file_path)?;
    let mut analysis = CodeAnalysis::new(file_path.to_path_buf(), code.clone());
    
    let ast = parse_file(&code)?;
    let mut visitor = SecurityVisitor::new(&mut analysis);
    visitor.visit_file(&ast);

    analysis.buffer_overflow = detect_buffer_overflow(&code);
    analysis.sql_injection = detect_sql_injection(&code);
    analysis.xss = detect_xss(&code);
    analysis.command_injection = detect_command_injection(&code);
    analysis.path_traversal = detect_path_traversal(&code);
    analysis.memory_leak = detect_memory_leak(&code);
    analysis.integer_overflow = detect_integer_overflow(&code);
    analysis.race_condition = detect_race_condition(&code);
    analysis.use_after_free = detect_use_after_free(&code);
    analysis.null_ptr_deref = detect_null_ptr_deref(&code);
    analysis.uninit_memory = detect_uninit_memory(&code);
    analysis.double_free = detect_double_free(&code);
    analysis.format_string = detect_format_string_vuln(&code);
    analysis.insecure_crypto = detect_insecure_crypto(&code);
    analysis.insecure_deserialization = detect_insecure_deserialization(&code);
    analysis.improper_error_handling = detect_improper_error_handling(&code);
    analysis.incorrect_lifetime = detect_incorrect_lifetime(&code);
    analysis.unsafe_ffi = detect_unsafe_ffi(&code);
    analysis.type_confusion = detect_type_confusion(&code);
    analysis.side_channel = detect_side_channel(&code);
    analysis.dos = detect_dos(&code);
    analysis.improper_input_validation = detect_improper_input_validation(&code);
    analysis.insecure_randomness = detect_insecure_randomness(&code);
    analysis.hardcoded_secrets = detect_hardcoded_secrets(&code);
    analysis.logging_sensitive_info = detect_sensitive_logging(&code);
    analysis.insecure_dependency = detect_insecure_dependencies(&code);
    analysis.improper_privileges = detect_privilege_issues(&code);
    analysis.business_logic_flaw = detect_business_logic_flaws(&code);
    analysis.unvalidated_recursion = detect_recursion_issues(&code);
    analysis.unbounded_allocation = detect_unbounded_allocation(&code);

    Ok(analysis)
}

struct SecurityVisitor<'a> {
    analysis: &'a mut CodeAnalysis,
}

impl<'a> SecurityVisitor<'a> {
    fn new(analysis: &'a mut CodeAnalysis) -> Self {
        Self { analysis }
    }
}

impl<'ast> Visit<'ast> for SecurityVisitor<'ast> {
    fn visit_expr_unsafe(&mut self, _: &'ast syn::ExprUnsafe) {
        self.analysis.unsafe_blocks += 1;
    }

    fn visit_expr_call(&mut self, expr: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*expr.func {
            let path_str: String = path.path.segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");
            
            if path_str.contains("unsafe") {
                self.analysis.unsafe_ffi = true;
            }
            if path_str.contains("transmute") {
                self.analysis.type_confusion = true;
            }
        }
        syn::visit::visit_expr_call(self, expr);
    }
}

fn detect_buffer_overflow(code: &str) -> bool {
    Regex::new(r"(?i)(memcpy|memmove|memset|gets|strcpy|strcat|sprintf|vsprintf)")
        .unwrap().is_match(code)
}

fn detect_sql_injection(code: &str) -> bool {
    Regex::new(r"(?i)(SELECT|INSERT|UPDATE|DELETE).*\+.*\b(user|password|input)\b")
        .unwrap().is_match(code)
}

fn detect_xss(code: &str) -> bool {
    Regex::new(r"(?i)(innerHTML|outerHTML|document\.write).*\+.*\b(user|input)\b")
        .unwrap().is_match(code)
}

fn detect_command_injection(code: &str) -> bool {
    Regex::new(r"(?i)Command::new|std::process::Command").unwrap().is_match(code)
}

fn detect_path_traversal(code: &str) -> bool {
    Regex::new(r"(?i)File::open|std::fs::read").unwrap().is_match(code)
}

fn detect_memory_leak(code: &str) -> bool {
    Regex::new(r"(?i)(Box::leak|mem::forget|Rc::new|Arc::new).*\(.*\)")
        .unwrap().is_match(code)
}

fn detect_integer_overflow(code: &str) -> bool {
    Regex::new(r"as\s+(u8|u16|u32|u64|usize|i8|i16|i32|i64|isize)").unwrap().is_match(code)
}

fn detect_race_condition(code: &str) -> bool {
    Regex::new(r"(?i)(unsafe|RefCell|Cell|static mut)").unwrap().is_match(code)
}

fn detect_use_after_free(code: &str) -> bool {
    Regex::new(r"(?i)(transmute|from_raw_parts|from_raw)").unwrap().is_match(code)
}

fn detect_null_ptr_deref(code: &str) -> bool {
    Regex::new(r"(?i)(\.unwrap\(\)|\.expect\(|unsafe\s*\{\s*\*)")
        .unwrap().is_match(code)
}

fn detect_uninit_memory(code: &str) -> bool {
    Regex::new(r"(?i)(mem::uninitialized|MaybeUninit::uninit\(\))")
        .unwrap().is_match(code)
}

fn detect_double_free(code: &str) -> bool {
    Regex::new(r"(?i)(Box::from_raw|mem::forget|ManuallyDrop)").unwrap().is_match(code)
}

fn detect_format_string_vuln(code: &str) -> bool {
    Regex::new(r#"(?i)(println!|format!|panic!).*\{.*:.*\}"#).unwrap().is_match(code)
}

fn detect_insecure_crypto(code: &str) -> bool {
    Regex::new(r"(?i)(md5|sha1|des|rc4)").unwrap().is_match(code)
}

fn detect_insecure_deserialization(code: &str) -> bool {
    Regex::new(r"(?i)serde_json::from_str|bincode::deserialize").unwrap().is_match(code)
}

fn detect_improper_error_handling(code: &str) -> bool {
    Regex::new(r"(?i)unwrap\(\)|expect\(").unwrap().is_match(code)
}

fn detect_incorrect_lifetime(code: &str) -> bool {
    Regex::new(r"(?i)'static\s+[^=]").unwrap().is_match(code)
}

fn detect_unsafe_ffi(code: &str) -> bool {
    Regex::new(r"(?i)extern\s*\{.*\}").unwrap().is_match(code)
}

fn detect_type_confusion(code: &str) -> bool {
    Regex::new(r"(?i)transmute").unwrap().is_match(code)
}

fn detect_side_channel(code: &str) -> bool {
    Regex::new(r"(?i)(secret|password|key).*\.as_bytes\(\)")
        .unwrap().is_match(code)
}

fn detect_dos(code: &str) -> bool {
    Regex::new(r"(?i)(loop\s*\{\s*panic!|while\s+true)")
        .unwrap().is_match(code)
}

fn detect_improper_input_validation(code: &str) -> bool {
    Regex::new(r"(?i)(unwrap\(\)|expect\()")
        .unwrap().is_match(code)
}

fn detect_insecure_randomness(code: &str) -> bool {
    Regex::new(r"(?i)rand::thread_rng").unwrap().is_match(code)
}

fn detect_hardcoded_secrets(code: &str) -> bool {
    Regex::new(r#"(?i)"(API_KEY|SECRET|PASSWORD|PRIVATE_KEY)\s*=\s*"[^"]+""#).unwrap().is_match(code)
}

fn detect_sensitive_logging(code: &str) -> bool {
    Regex::new(r"(?i)(log::info!|log::debug!).*(password|secret|token)").unwrap().is_match(code)
}

fn detect_insecure_dependencies(code: &str) -> bool {
    Regex::new(r#""([a-zA-Z0-9_-]+)"\s*=\s*"\*""#).unwrap().is_match(code)
}

fn detect_privilege_issues(code: &str) -> bool {
    Regex::new(r"(?i)(sudo|chmod|chown)").unwrap().is_match(code)
}

fn detect_business_logic_flaws(code: &str) -> bool {
    Regex::new(r"(?i)unwrap\(\)|expect\(").unwrap().is_match(code)
}

fn detect_recursion_issues(code: &str) -> bool {
    Regex::new(r"(?i)fn\s+\w+\(.*\)\s*->\s*\w+\s*\{.*\w+\(.*\)").unwrap().is_match(code)
}

fn detect_unbounded_allocation(code: &str) -> bool {
    Regex::new(r"(?i)Vec::with_capacity\(\d+\)").unwrap().is_match(code)
}