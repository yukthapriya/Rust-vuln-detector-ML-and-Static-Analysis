use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn main() {
    let mut metadata = vec!["unsafe_block,path_traversal,command_injection,function_count,clippy_warnings,label".to_string()];

    // Process unsafe snippets
    for i in 1..=51 {
        let path = format!("dataset/unsafe/unsafe_snippet_{}.rs", i);
        if let Some(entry) = process_snippet(&path, "unsafe") {
            metadata.push(entry);
        }
    }

    // Process safe snippets
    for i in 1..=51 {
        let path = format!("dataset/safe/safe_snippet_{}.rs", i);
        if let Some(entry) = process_snippet(&path, "safe") {
            metadata.push(entry);
        }
    }

    fs::write("dataset/metadata.csv", metadata.join("\n")).unwrap();
    println!("Generated metadata.csv with {} entries", metadata.len() - 1);
}

fn process_snippet(path: &str, label: &str) -> Option<String> {
    let code = fs::read_to_string(path).ok()?;

    // Create temp Cargo project
    let temp_dir = TempDir::new().ok()?;
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).ok()?;
    fs::write(src_dir.join("main.rs"), &code).ok()?;
    fs::write(temp_dir.path().join("Cargo.toml"), 
        "[package]\nname = \"temp\"\nversion = \"0.1.0\"\nedition = \"2021\"\n").ok()?;

    let unsafe_blocks = code.matches("unsafe").count();
    let path_traversal = detect_path_traversal(&code) as u8;
    let command_injection = detect_command_injection(&code) as u8;
    let function_count = code.matches("fn ").count();
    let clippy_warnings = run_clippy(temp_dir.path());

    Some(format!(
        "{},{},{},{},{},{}",
        unsafe_blocks, path_traversal, command_injection, 
        function_count, clippy_warnings, label
    ))
}

fn detect_path_traversal(code: &str) -> bool {
    code.contains("Path::new") && code.contains("user_input")
}

fn detect_command_injection(code: &str) -> bool {
    code.contains("Command::new") && code.contains("untrusted_input")
}

fn run_clippy(project_path: &std::path::Path) -> usize {
    let output = Command::new("cargo")
        .current_dir(project_path)
        .args(["clippy", "--quiet", "--", "-D", "warnings"])
        .output()
        .unwrap_or_else(|_| panic!("Failed to run clippy"));

    String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|line| line.contains("warning: "))
        .count()
}