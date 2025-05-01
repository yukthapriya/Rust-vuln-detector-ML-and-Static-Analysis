#!/bin/bash
set -eo pipefail

echo "🚀 Generating LLVM IR for all files..."
echo "-------------------------------------"

# Configuration
INPUT_DIRS=("dataset/safe" "dataset/unsafe")
OUTPUT_DIRS=("ir/safe" "ir/unsafe")
LOG_FILE="ir_generation.log"

# Initialize
rm -rf ir/* && mkdir -p "${OUTPUT_DIRS[@]}"
> "$LOG_FILE"

process_file() {
    local file=$1
    local category=$2
    local base=$(basename "$file" .rs)
    local out_dir="ir/$category"
    
    echo "🔧 Processing $category: $base.rs" | tee -a "$LOG_FILE"
    
    local tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT
    
    (
        mkdir -p "$tmp_dir/src"
        cp "$file" "$tmp_dir/src/main.rs"
        cd "$tmp_dir"

        # Create header with proper attribute order
        header="#![allow(unused_imports)]\n"
        header+="#![allow(unused_variables)]\n"
        header+="#![allow(dead_code)]\n"
        header+="#![allow(unused_mut)]\n"

        # Add required imports
        declare -a imports=(
            'use std::fs::File;'
            'use std::path::Path;'
            'use std::sync::{Arc, Mutex};'
            'use std::mem::MaybeUninit;'
            'use std::alloc::{Layout, alloc, dealloc};'  # Critical fix
        )
        
        for import in "${imports[@]}"; do
            if ! grep -qF "$import" src/main.rs; then
                header+="$import\n"
            fi
        done

        # Add unsafe-specific imports
        if [ "$category" = "unsafe" ]; then
            header+="use std::ptr;\n"
            header+="use std::arch::asm;\n"
        fi
# In the process_file() function, after preprocessing:
sed -i '' '/^rust$/d' src/main.rs
        # Prepend header to main.rs
        echo -e "$header$(cat src/main.rs)" > src/main.rs

        # Add enum if missing
        if ! grep -qE 'enum [A-Z][a-zA-Z0-9_]*' src/main.rs; then
            sed -i '' '/^fn /i\
#[derive(Debug)]\
enum Foo {\
    A(i32),\
    B(f32)\
}\
' src/main.rs
        fi

        # Add main function if missing
        if ! grep -q 'fn main()' src/main.rs; then
            echo -e "\nfn main() {\n    // Auto-generated entry point\n}" >> src/main.rs
        fi

        # Initialize Cargo project
        cargo init --name "temp_$base" --vcs none >/dev/null
        echo 'libc = "0.2"' >> Cargo.toml
        echo 'tokio = { version = "1.0", features = ["full"] }' >> Cargo.toml
        
        # Build with IR emission
        RUSTFLAGS="--emit=llvm-ir" cargo build --release || return 1
        
        # Move generated IR file
        find target/release -name '*.ll' -exec mv {} "$OLDPWD/$out_dir/${base}.ll" \;
    ) || {
        echo "❌ Failed $base.rs" | tee -a "$LOG_FILE"
        return 1
    }
}

# Process files
for i in "${!INPUT_DIRS[@]}"; do
    input_dir="${INPUT_DIRS[$i]}"
    output_dir="${OUTPUT_DIRS[$i]}"
    
    find "$input_dir" -name '*.rs' | while read -r file; do
        process_file "$file" "$(basename "$output_dir")"
    done
done

echo "✅ Generation completed!"
echo "========================"
echo "Safe files:   $(find ir/safe -name '*.ll' | wc -l)/50"
echo "Unsafe files: $(find ir/unsafe -name '*.ll' | wc -l)/50"
echo "========================"
echo "Check $LOG_FILE for any errors"