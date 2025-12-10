//! WASM build script for Hegemon runtime
//!
//! This generates the WASM binary that the node executor runs.
//! The generated binary is embedded in the runtime crate and exported
//! as `WASM_BINARY` and `WASM_BINARY_BLOATY`.
//!
//! # Build Process
//!
//! 1. `substrate-wasm-builder` compiles runtime to WebAssembly
//! 2. Output placed in `target/*/wbuild/runtime/`
//! 3. Binary is embedded via include_bytes! in lib.rs
//!
//! # Requirements
//!
//! - Rust nightly with wasm32-unknown-unknown target
//! - `substrate-wasm-builder` in build-dependencies

fn main() {
    #[cfg(feature = "std")]
    {
        // Skip WASM build in CI or when explicitly requested
        // This allows native-only compilation for development
        if std::env::var("SKIP_WASM_BUILD").is_ok() {
            // Create a placeholder wasm_binary.rs when skipping WASM build
            let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
            let dest_path = std::path::Path::new(&out_dir).join("wasm_binary.rs");
            std::fs::write(
                &dest_path,
                r#"
                /// WASM binary not available - built with SKIP_WASM_BUILD
                pub const WASM_BINARY: Option<&[u8]> = None;
                /// WASM binary not available - built with SKIP_WASM_BUILD
                pub const WASM_BINARY_BLOATY: Option<&[u8]> = None;
                "#,
            )
            .expect("Failed to write wasm_binary.rs placeholder");
            return;
        }

        substrate_wasm_builder::WasmBuilder::new()
            .with_current_project()
            .export_heap_base()
            .import_memory()
            .disable_runtime_version_section_check()
            // getrandom 0.3 requires custom backend cfg for wasm32
            .append_to_rust_flags("--cfg=getrandom_backend=\"custom\"")
            .build();
    }
}
