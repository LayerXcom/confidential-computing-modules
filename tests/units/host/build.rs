use std::env;

fn main () {
    let sdk_dir = env::var("SGX_SDK")
                    .unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());
    let rust_sgx_sdk = env::var("SGX_SDK_RUST")
        .unwrap_or_else(|_| format!("{}/sgx", dirs::home_dir().unwrap().display()));
    let edl = format!("{}/edl", rust_sgx_sdk);
    let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
    match is_sim.as_ref() {
        "SW" => {
            println!("cargo:rustc-link-lib=dylib=sgx_urts_sim");
            println!("cargo:rustc-link-lib=dylib=sgx_uae_service_sim");
        }
        _ => {
            // Treat both HW and undefined as HW
            println!("cargo:rustc-link-lib=dylib=sgx_urts");
            println!("cargo:rustc-link-lib=dylib=sgx_uae_service");
        }
    }

    cc::Build::new()
        .file("Anonify_test_u.c")
        .include("/opt/sgxsdk/include")
        .include(edl)
        .compile("libAnonify_test_u.a");
}
