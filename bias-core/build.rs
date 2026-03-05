fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "decompiler")]
    build_decompiler()?;
    Ok(())
}

#[cfg(feature = "decompiler")]
fn build_decompiler() -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    use std::path::{Path, PathBuf};

    const DECOMPILER_INCLUDES: &[&str] = &["cxx"];

    let mut decompiler_config = cmake::Config::new("cxx");
    decompiler_config
        .cxxflag("-U_GLIBCXX_ASSERTIONS");

    #[cfg(target_os = "windows")]
    decompiler_config.cxxflag("-D_WINDOWS"); // the decompiler depends on it...

    let decompiler = decompiler_config.build();

    let dst = PathBuf::from_iter(&[decompiler.as_ref(), Path::new("lib")]);

    println!("cargo:rustc-link-search=native={}", dst.display());

    println!("cargo:rustc-link-lib=static:-bundle,+whole-archive=ghidra_base");
    println!("cargo:rustc-link-lib=static:-bundle,+whole-archive=ghidra_sleigh");
    println!("cargo:rustc-link-lib=static:-bundle,+whole-archive=ghidra_decompiler");
    println!("cargo:rustc-link-lib=static:-bundle,+whole-archive=ghidra_libdecomp");
    println!("cargo:rustc-link-lib=static:-bundle,+whole-archive=pugixml");
    println!("cargo:rustc-link-lib=static:-bundle,+whole-archive=decompiler_ffi");

    cxx_build::CFG.include_prefix = "";
    cxx_build::bridge("src/decompiler/ffi.rs")
        .includes(DECOMPILER_INCLUDES)
        .flag("-U_GLIBCXX_ASSERTIONS")
        .flag_if_supported("-std=c++20")
        .flag_if_supported("/std:c++20")
        .opt_level(
            if matches!(env::var("PROFILE"), Ok(profile) if profile == "release") {
                3
            } else {
                0
            },
        )
        .warnings(false)
        .try_compile("decompiler_bridge")?;

    println!("cargo:rerun-if-changed=src/decompiler/ffi.rs");

    println!("cargo:rerun-if-changed=cxx/bridge.hh");
    println!("cargo:rerun-if-changed=cxx/rust.hh");

    println!("cargo:rerun-if-changed=cxx/decompiler.cc");
    println!("cargo:rerun-if-changed=cxx/decompiler.hh");

    println!("cargo:rerun-if-changed=cxx/decompiler_annot.cc");
    println!("cargo:rerun-if-changed=cxx/decompiler_annot.hh");

    println!("cargo:rerun-if-changed=cxx/decompiler_arch.cc");
    println!("cargo:rerun-if-changed=cxx/decompiler_arch.hh");

    println!("cargo:rerun-if-changed=cxx/decompiler_loadimage.cc");
    println!("cargo:rerun-if-changed=cxx/decompiler_loadimage.hh");

    println!("cargo:rerun-if-changed=cxx/decompiler_scope.cc");
    println!("cargo:rerun-if-changed=cxx/decompiler_scope.hh");

    println!("cargo:rerun-if-changed=cxx/printc2.cc");
    println!("cargo:rerun-if-changed=cxx/printc2.hh");

    println!("cargo:rerun-if-changed=cxx/CMakeLists.txt");
    println!("cargo:rerun-if-changed=cxx/decompiler/CMakeLists.txt");

    Ok(())
}
