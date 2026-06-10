fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The proto lives outside this package, so it is not covered by cargo's
    // default change tracking; declare it explicitly so edits regenerate code.
    println!("cargo:rerun-if-changed=../../proto/ca_service.proto");
    println!("cargo:rerun-if-changed=build.rs");

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["../../proto/ca_service.proto"], &["../../proto"])?;
    Ok(())
}
