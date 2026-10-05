fn main() {
    println!("cargo:rerun-if-changed=../../proto/ark_envelope.proto");
    
    // Attempt prost_build compilation if protoc is installed
    if std::env::var("PROTOC").is_ok() || which_protoc() {
        let mut config = prost_build::Config::new();
        config
            .compile_protos(&["../../proto/ark_envelope.proto"], &["../../proto"])
            .expect("Failed to compile protobuf schemas");
    }
}

fn which_protoc() -> bool {
    std::process::Command::new("protoc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
