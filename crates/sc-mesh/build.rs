fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_path = "../../proto/mesh.proto";
    // Only build if the proto file exists
    if std::path::Path::new(proto_path).exists() {
        tonic_build::compile_protos(proto_path)?;
    }
    Ok(())
}
