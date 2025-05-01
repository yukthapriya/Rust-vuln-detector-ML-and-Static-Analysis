use regex::Regex;
use syn::{visit::Visit, ItemForeignMod, Expr};

#[derive(Default)]
pub struct CodeFeatures {
    pub unsafe_blocks: usize,
    pub raw_pointers: usize,
    pub ffi_functions: usize,
    pub path_traversal: bool,
    pub command_injection: bool,
    pub double_free_risk: bool,
    pub data_race_risk: bool,
    pub uninitialized_memory: bool,
    pub panic_in_unsafe: bool,
    pub arithmetic_overflow: bool,
    pub dangling_references: bool,
    pub improper_lifetime: bool,
    pub insecure_crypto: bool,
    pub unchecked_unwrap: bool,
    pub deprecated_functions: bool,
    pub function_count: usize,
    pub clippy_warnings: usize,
}

pub fn extract_features(code: &str) -> CodeFeatures {
    let mut features = CodeFeatures::default();
    let ast = syn::parse_file(code).unwrap_or_else(|_| syn::parse_file("").unwrap());

    // Basic checks
    features.unsafe_blocks = code.matches("unsafe").count();
    features.raw_pointers = code.matches("*const").count() + code.matches("*mut").count();
    features.path_traversal = Regex::new(r"Path::new\(.*\)").unwrap().is_match(code);
    features.command_injection = Regex::new(r"Command::new\(.*\)").unwrap().is_match(code);
    features.function_count = code.matches("fn ").count();
    features.clippy_warnings = 0; // Clippy warnings require runtime analysis, set to 0 for static analysis

    // Advanced semantic checks
    let mut visitor = AdvancedVisitor::new(&mut features);
    visitor.visit_file(&ast);

    // Regex-based checks
    features.insecure_crypto = detect_insecure_crypto(code);
    features.deprecated_functions = detect_deprecated_functions(code);
    features.unchecked_unwrap = detect_unchecked_unwrap(code);

    features
}

struct AdvancedVisitor<'a> {
    features: &'a mut CodeFeatures,
    current_unsafe_depth: u32,
}

impl<'a> AdvancedVisitor<'a> {
    fn new(features: &'a mut CodeFeatures) -> Self {
        AdvancedVisitor { features, current_unsafe_depth: 0 }
    }
}

impl<'ast> Visit<'ast> for AdvancedVisitor<'ast> {
    fn visit_item_foreign_mod(&mut self, node: &'ast ItemForeignMod) {
        self.features.ffi_functions += node.items.len();
    }

    fn visit_expr_unsafe(&mut self, _: &'ast syn::ExprUnsafe) {
        self.features.unsafe_blocks += 1;
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*node.func {
            let func_name = path.path.segments.last().unwrap().ident.to_string();
            if matches!(func_name.as_str(), "transmute" | "uninitialized" | "forget") {
                self.features.double_free_risk = true;
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if let syn::BinOp::Add(_) | syn::BinOp::Sub(_) | 
           syn::BinOp::Mul(_) | syn::BinOp::Div(_) = node.op {
            self.features.arithmetic_overflow = true;
        }
        syn::visit::visit_expr_binary(self, node);
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        if block.stmts.iter().any(|stmt| {
            matches!(stmt, syn::Stmt::Expr(syn::Expr::Unsafe(_), _))
        }) {
            self.current_unsafe_depth += 1;
            check_unsafe_block_vulnerabilities(block, self.features);
        }
        syn::visit::visit_block(self, block);
        self.current_unsafe_depth -= 1;
    }
}

fn check_unsafe_block_vulnerabilities(block: &syn::Block, features: &mut CodeFeatures) {
    for stmt in &block.stmts {
        if let syn::Stmt::Expr(syn::Expr::Macro(syn::ExprMacro { mac, .. }), _) = stmt {
            if mac.path.is_ident("panic") {
                features.panic_in_unsafe = true;
            }
        }
    }
}

fn detect_insecure_crypto(code: &str) -> bool {
    Regex::new(r#"(?i)\b(md5|sha1|des|rc4)\b"#).unwrap().is_match(code)
}

fn detect_deprecated_functions(code: &str) -> bool {
    Regex::new(r#"\b(env::set_var|std::old_io|std::ascii)\b"#).unwrap().is_match(code)
}

fn detect_unchecked_unwrap(code: &str) -> bool {
    Regex::new(r#"\bunwrap\(\)|expect\([^)]*\)"#).unwrap().is_match(code)
}