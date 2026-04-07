use std::{env, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let vendor = manifest_dir.join("../../vendor/smallwood-prototype");
    let csrc = manifest_dir.join("csrc/smallwood_candidate.c");

    println!("cargo:rerun-if-changed={}", csrc.display());
    println!("cargo:rerun-if-changed={}", vendor.display());

    let include_dirs = [
        vendor.join("smallwood"),
        vendor.join("smallwood/field"),
        vendor.join("smallwood/field/generic"),
        vendor.join("smallwood/merkle"),
        vendor.join("smallwood/merkle/generic"),
        vendor.join("smallwood/decs"),
        vendor.join("smallwood/lvcs"),
        vendor.join("smallwood/pcs"),
        vendor.join("smallwood/lppc"),
        vendor.join("smallwood/piop"),
        vendor.join("smallwood/smallwood"),
        vendor.join("smallwood/benchmark"),
        vendor.join("capss"),
        vendor.join("capss/f64"),
        vendor.join("capss/hash-implem"),
    ];

    let sources = [
        vendor.join("smallwood/lppc/lppc.c"),
        vendor.join("smallwood/piop/piop.c"),
        vendor.join("smallwood/piop/piop-alloc.c"),
        vendor.join("smallwood/decs/decs.c"),
        vendor.join("smallwood/decs/decs-alloc.c"),
        vendor.join("smallwood/lvcs/lvcs.c"),
        vendor.join("smallwood/lvcs/lvcs-alloc.c"),
        vendor.join("smallwood/pcs/pcs.c"),
        vendor.join("smallwood/pcs/pcs-alloc.c"),
        vendor.join("smallwood/smallwood/smallwood.c"),
        vendor.join("smallwood/smallwood/smallwood-alloc.c"),
        vendor.join("smallwood/merkle/generic/merkle.c"),
        vendor.join("smallwood/merkle/generic/merkle-alloc.c"),
        vendor.join("capss/hash-implem/merkle-hash.c"),
        vendor.join("capss/hash-implem/lvcs-hash.c"),
        vendor.join("capss/hash-implem/decs-hash.c"),
        vendor.join("capss/hash-implem/piop-hash.c"),
        vendor.join("capss/hash-implem/smallwood-hash.c"),
        csrc,
    ];

    let mut build = cc::Build::new();
    build.warnings(false);
    build.flag_if_supported("-std=gnu2x");
    build.flag_if_supported("-std=c23");
    build.flag_if_supported("-std=c17");
    build.flag_if_supported("-Wno-bit-int-extension");

    for include in include_dirs {
        build.include(include);
    }
    for source in sources {
        build.file(source);
    }

    build.compile("hegemon_smallwood_candidate");
}
