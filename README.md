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

 Experiment Setup and Methodology
Add this after the installation and usage instructions:
## 🧪 Experiment Methodology

1. **Dataset Preparation**: 102 Rust code snippets (51 safe, 51 unsafe), labeled and stored with metadata.
2. **Static Analysis**: Run Clippy and a custom analyzer to extract code features like `unsafe` usage and insecure APIs.
3. **Feature Engineering**: Use `data_loader.rs` to generate features from AST and lint data.
4. **Model Training**: Train logistic regression using the `linfa` crate (80% train, 20% test).
5. **Evaluation**: Generate `security_report.csv`, compute accuracy, precision, and recall.

✅ **Model Accuracy:** 83%
📈 Results and Evaluation
This showcases your effectiveness:
## 📈 Results

- Achieved **83% accuracy** using logistic regression
- Detected vulnerabilities such as:
  - Unsafe memory operations
  - Command injection risks
  - Path traversal attempts
- Model outputs include classification and a confidence score per file

## 📂 Project Structure

├── dataset/ # Safe and unsafe Rust code samples
├── metadata.csv # Annotated features for each snippet
├── data_loader.rs # Converts analysis results to features
├── static_analysis.rs # Custom AST analysis using syn crate
├── ml.rs # Logistic regression training & prediction
├── security_report.csv # Output with predictions and scores
└── README.md
## 🔮 Future Work

- Expand dataset to improve model generalization
- Explore advanced ML models (e.g., decision trees, SVMs)
- Integrate tools like Rudra or `cargo-audit`
- Automate pipeline integration in CI for real-time vulnerability checks
