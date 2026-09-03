//! Generate the contract lineages from the checked-in registries.
//!
//! Codegen rather than hand-written constants so the registry TOML is the
//! single source of truth: a hash recorded there cannot fail to reach the
//! probe because somebody forgot to copy it into Rust.

use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("bridge/ has a parent")
        .to_path_buf();

    for (file, out, const_name) in [
        (
            "legacy/address_contract.toml",
            "legacy_address_contract.rs",
            "LEGACY_ADDRESS_CONTRACT_HASHES",
        ),
        (
            "legacy/tip_contract.toml",
            "legacy_tip_contract.rs",
            "LEGACY_TIP_CONTRACT_HASHES",
        ),
    ] {
        let path = root.join(file);

        // An absent or empty registry must FAIL the build, never silently
        // produce an empty lineage. An empty lineage probes nothing, finds
        // nothing, and reports success -- the failure mode that loses data
        // while looking healthy.
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read migration registry {}: {e}", path.display()));
        if !text.contains("[[entry]]") {
            panic!(
                "migration registry {} has no [[entry]] rows. An empty lineage \
                 probes nothing and reports success. If this is genuinely the \
                 first generation, say so with an explicit comment and remove \
                 this guard deliberately.",
                path.display()
            );
        }

        freenet_migrate_build::codegen()
            .entry_registry(&path, freenet_migrate_build::Component::Contract)
            .out_file(out)
            .contract_const_name(const_name)
            .emit()
            .unwrap_or_else(|e| panic!("codegen for {}: {e}", path.display()));

        // Without this, editing the registry does not invalidate the cached
        // build script and the generated lineage silently goes stale. River
        // shipped for months with exactly that gap.
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rerun-if-changed=build.rs");
}
