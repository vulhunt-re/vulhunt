mod error;
mod loaded_binary;
mod loader;
mod platform;
mod source;
mod util;

pub use error::BNDBSourceError;
pub use loaded_binary::BNDBLoadedBinary;
pub use loader::BNDBBinaryLoader;
pub use source::{BNDBData, BNDBSource};

#[cfg(test)]
mod test {
    use std::path::Path;

    use bias::component::ComponentLoader;
    use bias::loader::BA2PackageLoader;
    use bias::loader::meta::BA2ComponentMetadataSource;
    use bias::pipeline::{PipelineError, Source};
    use bias::platform::PlatformProvider;
    use bias::platform::posix::PosixBinary;
    use bias_core::ProjectConfig;

    use crate::source::BNDBSource;

    #[tokio::test]
    async fn test_bndb_source() -> Result<(), PipelineError> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/libipmi.so.bndb");
        let source = BNDBSource::from_file(path).expect("test BNDB should load successfully");

        let data_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../data");
        let loader = ComponentLoader::new_with(data_path).expect("data directory should exist");

        let pid = source.package_id();
        let cid = source.component_id();

        let meta = source
            .component_meta_by_uuid(&pid, &cid)?
            .expect("component metadata should be found");

        assert_eq!(meta.id(), cid, "metadata ID should match component ID");

        let platform = meta.platform().expect("metadata platform should be valid");

        assert_eq!(
            platform.name(),
            PosixBinary::NAME,
            "platform name should match"
        );

        let components = source.components(&pid).collect::<Vec<_>>();

        assert_eq!(
            components,
            vec![cid],
            "components should contain the expected component ID"
        );

        let _package = source
            .package_by_uuid(&pid)
            .expect("package should be found");

        let component = source
            .component_by_uuid(&pid, &cid)?
            .expect("component should be found");

        let loaded = source
            .load_component(
                &loader,
                pid,
                cid,
                component.bytes().into(),
                component.platform().to_owned(),
            )
            .expect("component should load successfully");

        let (lifter, binary) = loaded
            .into_binary_parts()
            .expect("component should be a binary");

        let project = binary
            .project_loader()
            .expect("binary should have a project loader")
            .load_project(&binary, lifter, &ProjectConfig::default())
            .expect("project should load successfully");

        for f in project.functions().values() {
            println!(
                "function at {} named {:?} ~ {:?}",
                f.address(),
                f.name(),
                f.properties()
            );
        }

        Ok(())
    }
}
