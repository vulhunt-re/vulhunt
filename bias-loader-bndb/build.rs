use std::env;

fn main() {
    let link_path =
        env::var("DEP_BINARYNINJACORE_PATH").expect("DEP_BINARYNINJACORE_PATH not specified");

    println!("cargo:rustc-link-search=native={link_path}");
    println!("cargo:rustc-link-lib=dylib=binaryninjacore");

    #[cfg(target_os = "linux")]
    {
        println!(
            "cargo::rustc-link-arg=-Wl,-rpath,{link_path},-L{link_path},-l:libbinaryninjacore.so",
        );
    }

    #[cfg(target_os = "macos")]
    {
        println!("cargo::rustc-link-arg=-Wl,-rpath,{link_path},-L{link_path},-lbinaryninjacore",);
    }
}
