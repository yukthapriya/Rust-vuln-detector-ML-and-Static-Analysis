# Rust-vuln-detector-ML-and-Static-Analysis

Rust ensures performance and memory safety, but unsafe blocks and dependencies can introduce vulnerabilities. We present a tool combining machine learning and static analysis to detect issues like command injection and path traversal. Using 102 Rust snippets, features from Clippy train a logistic regression model to classify code safety. The tool outputs reports with confidence scores, enhancing Rust security.
