# Rust-vuln-detector-ML-and-Static-Analysis

# 🔐 Rust Vulnerability Detector using Machine Learning & Static Analysis

A hybrid tool that combines **static analysis** and **machine learning** to detect **security vulnerabilities in Rust codebases**, focusing on `unsafe` blocks, command injection, and path traversal.

## 🧠 Overview

Rust is designed for memory safety and performance. However, improper use of `unsafe` code or untrusted external dependencies can introduce vulnerabilities. This project uses:

- 🔍 **Clippy + Custom Static Analyzer**  
- 🧮 **Logistic Regression Model** (via `linfa` crate)  
- 📊 **Security Reports** with confidence scores

## 📁 Dataset

- `dataset/safe/` and `dataset/unsafe/`: 102 Rust code snippets (51 safe, 51 unsafe)
- `metadata.csv`: Metadata and features (e.g., number of `unsafe` blocks, function count, command injection)

## ⚙️ Components

| Module                | Purpose                                           |
|------------------------|---------------------------------------------------|
| `static_analysis.rs`   | Analyzes AST for unsafe patterns                  |
| `data_loader.rs`       | Extracts features from Clippy and AST             |
| `ml.rs`                | Trains logistic regression using `linfa` crate    |
| `security_report.csv`  | Outputs model predictions with confidence scores  |

## 🔍 Key Features

- Detects:
  - Unsafe blocks
  - Command injection
  - Path traversal risks
- Generates confidence-based CSV vulnerability reports
- Achieved **83% accuracy** in detecting unsafe Rust code

## 🧪 How It Works

1. **Static Analysis** → Run Clippy & custom AST checker
2. **Feature Extraction** → Convert outputs to ML-ready features
3. **ML Model Training** → Logistic regression model with `linfa`
4. **Report Generation** → Output predictions + confidence scores

