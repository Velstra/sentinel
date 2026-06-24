//! Nix build shim for velstra-app/build.rs.
//!
//! In the Nix build the eBPF object is compiled by a separate fixed-output
//! derivation (which is allowed network for `-Z build-std`). This replaces the
//! normal aya-build invocation: instead of building the eBPF here (which would
//! need offline build-std and fail in the sandbox), it copies the pre-built
//! object the derivation hands us via $VELSTRA_EBPF_OBJ into $OUT_DIR/velstra,
//! exactly where the agent's `include_bytes_aligned!(OUT_DIR/velstra)` expects.

use std::{env, fs, path::Path};

fn main() {
    println!("cargo:rerun-if-env-changed=VELSTRA_EBPF_OBJ");
    let obj = env::var("VELSTRA_EBPF_OBJ")
        .expect("VELSTRA_EBPF_OBJ must point at the pre-built eBPF object");
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    let dst = Path::new(&out_dir).join("velstra");
    fs::copy(&obj, &dst).unwrap_or_else(|e| panic!("copying {obj} -> {}: {e}", dst.display()));
}
