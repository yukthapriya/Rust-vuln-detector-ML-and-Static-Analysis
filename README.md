
# 🔐 Rust Vuln Detector using Machine Learning & Static Analysis

This project presents a hybrid tool that uses **static analysis** and **machine learning** to detect vulnerabilities in Rust code, focusing on:
- `unsafe` blocks
- command injection
- path traversal

## 🧠 Overview

Rust is known for performance and memory safety, but improper use of `unsafe` code and third-party dependencies can introduce critical vulnerabilities. This tool:
- Uses **Clippy** and a custom AST analyzer to extract code features
- Trains a **logistic regression** model using the `linfa` crate
- Generates **security reports** with predictions and confidence scores

---

## 🔍 Key Features

- Detects:
  - Unsafe memory operations
  - Command injection risks
  - Path traversal vulnerabilities
- Outputs CSV-based vulnerability reports with confidence scores
- Achieved **83% accuracy** in classification

---

## 📁 Dataset

- `dataset/safe/` and `dataset/unsafe/`: 102 Rust code snippets (51 safe, 51 unsafe)
- `metadata.csv`: Includes features such as:
  - `unsafe_block`
  - `command_injection`
  - `path_traversal`
  - `function_count`
  - Clippy warnings and enforcement flags

---

## 🧪 How It Works

1. **Static Analysis** → Run Clippy & custom AST checker
2. **Feature Extraction** → Convert outputs to ML-ready features
3. **ML Model Training** → Logistic regression model with `linfa`
4. **Report Generation** → Output predictions + confidence scores

---

## 🧪 Experiment Methodology

- **Dataset Preparation**: 102 Rust code snippets, labeled and stored with metadata
- **Static Analysis**: Run Clippy + custom parser to extract security-related patterns
- **Feature Engineering**: Extract features using `data_loader.rs`
- **Training & Evaluation**:
  - Train logistic regression using `linfa` (80/20 split)
  - Evaluate using accuracy, precision, and recall
- ✅ **Model Accuracy**: 83%

---

## 📈 Results

- Detected vulnerabilities:
  - Unsafe memory access
  - Dangerous shell commands
  - Unchecked file paths
- Output example:

File: main.rs
Unsafe Block: ✅
Command Injection: ⚠️
Path Traversal: ❌
Prediction: Unsafe (Confidence: 90%)

---

## 🔮 Future Work

- Expand the dataset to improve generalization
- Experiment with advanced ML models (SVMs, decision trees, etc.)
- Integrate with CI tools for continuous vulnerability scanning
- Extend to use tools like Rudra or `cargo-audit`
