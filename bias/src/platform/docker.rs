use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;
use std::path::{Path, PathBuf};

use bias_core::any::ProvidesStaticType;
use bias_core::kb::{uuid, Uuid};
use bias_core::loader::{LoaderAttribute, LoaderContainer};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

use super::{
    PlatformAttributeProvider, PlatformBuilder, PlatformComponentLoader, PlatformProvider,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct DockerImageConfig {
    #[serde(default, with = "timestamp_opt")]
    created: Option<DateTime<FixedOffset>>,
    #[serde(default)]
    author: Option<String>,
    architecture: String,
    os: String,
    #[serde(default)]
    config: Option<DockerImageExecutionConfig>,
    rootfs: DockerImageRootFS,
    #[serde(default, deserialize_with = "deserialise_option_as_default")]
    history: Vec<DockerImageLayerHistory>,
}

fn deserialise_option_as_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

mod timestamp_opt {
    use chrono::{DateTime, FixedOffset};
    use serde::Deserialize;

    pub(crate) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<DateTime<FixedOffset>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|ts| DateTime::parse_from_rfc3339(&ts))
            .transpose()
            .map_err(serde::de::Error::custom)
    }

    pub(crate) fn serialize<S>(
        date: &Option<DateTime<FixedOffset>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match date {
            Some(dt) => {
                let s = dt.to_rfc3339();
                serializer.serialize_some(&s)
            }
            None => serializer.serialize_none(),
        }
    }
}

impl DockerImageConfig {
    pub fn created(&self) -> Option<&DateTime<FixedOffset>> {
        self.created.as_ref()
    }

    pub fn author(&self) -> Option<&str> {
        self.author.as_deref()
    }

    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    pub fn os(&self) -> &str {
        &self.os
    }

    pub fn config(&self) -> Option<&DockerImageExecutionConfig> {
        self.config.as_ref()
    }

    pub fn rootfs(&self) -> &DockerImageRootFS {
        &self.rootfs
    }

    pub fn history(&self) -> &[DockerImageLayerHistory] {
        &self.history
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct DockerImageExecutionConfig {
    #[serde(default, alias = "User")]
    user: Option<String>,
    #[serde(
        default,
        alias = "ExposedPorts",
        deserialize_with = "deserialise_golang_empty_map"
    )]
    exposed_ports: BTreeSet<String>,
    #[serde(
        default,
        alias = "Cmd",
        deserialize_with = "deserialise_option_as_default"
    )]
    cmd: Vec<String>,
    #[serde(
        default,
        alias = "Env",
        deserialize_with = "deserialise_option_as_default"
    )]
    environment: Vec<String>,
    #[serde(
        default,
        alias = "Entrypoint",
        deserialize_with = "deserialise_option_as_default"
    )]
    entrypoint: Vec<String>,
    #[serde(
        default,
        alias = "Volumes",
        deserialize_with = "deserialise_golang_empty_map"
    )]
    volumes: BTreeSet<String>,
    #[serde(default, alias = "WorkingDir")]
    working_dir: Option<String>,
    #[serde(
        default,
        alias = "Labels",
        deserialize_with = "deserialise_option_as_default"
    )]
    labels: BTreeMap<String, String>,
    #[serde(default, alias = "StopSignal")]
    stop_signal: Option<String>,
}

impl DockerImageExecutionConfig {
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    pub fn exposed_ports(&self) -> &BTreeSet<String> {
        &self.exposed_ports
    }

    pub fn cmd(&self) -> &[String] {
        &self.cmd
    }

    pub fn environment(&self) -> &[String] {
        &self.environment
    }

    pub fn entrypoint(&self) -> &[String] {
        &self.entrypoint
    }

    pub fn volumes(&self) -> &BTreeSet<String> {
        &self.volumes
    }

    pub fn working_dir(&self) -> Option<&str> {
        self.working_dir.as_deref()
    }

    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }

    pub fn stop_signal(&self) -> Option<&str> {
        self.stop_signal.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct DockerImageRootFS {
    #[serde(default, rename = "type")]
    type_: String,
    diff_ids: Vec<String>,
}

impl DockerImageRootFS {
    pub fn r#type(&self) -> &str {
        &self.type_
    }

    pub fn diff_ids(&self) -> &[String] {
        &self.diff_ids
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct DockerImageLayerHistory {
    #[serde(default, with = "timestamp_opt")]
    created: Option<DateTime<FixedOffset>>,
    #[serde(default)]
    created_by: Option<String>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    empty_layer: bool,
}

fn deserialise_golang_empty_map<'de, D>(deserializer: D) -> Result<BTreeSet<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct EmptyStruct {}

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum GoSet {
        S(BTreeSet<String>),
        M(BTreeMap<String, EmptyStruct>),
    }

    let set = match Option::<GoSet>::deserialize(deserializer)? {
        None => BTreeSet::new(),
        Some(GoSet::S(set)) => set,
        Some(GoSet::M(map)) => map.into_keys().collect(),
    };

    Ok(set)
}

impl DockerImageLayerHistory {
    pub fn created(&self) -> Option<&DateTime<FixedOffset>> {
        self.created.as_ref()
    }

    pub fn created_by(&self) -> Option<&str> {
        self.created_by.as_deref()
    }

    pub fn author(&self) -> Option<&str> {
        self.author.as_deref()
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    pub fn empty_layer(&self) -> bool {
        self.empty_layer
    }
}

#[derive(ProvidesStaticType)]
pub struct DockerComponentImageConfig<'a>(&'a DockerImageConfig);
impl<'a> LoaderAttribute<'a> for DockerComponentImageConfig<'a> {
    const UUID: Uuid = uuid("35685CF4-CE40-48F6-AA52-7A23F215D0FA");
}

impl<'a> AsRef<DockerImageConfig> for DockerComponentImageConfig<'a> {
    fn as_ref(&self) -> &DockerImageConfig {
        self.0
    }
}

impl<'a> Deref for DockerComponentImageConfig<'a> {
    type Target = DockerImageConfig;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct DockerComponentLayer<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for DockerComponentLayer<'a> {
    const UUID: Uuid = uuid("CABCB0B0-2DFF-4B8F-87AE-414F571E922C");
}

impl<'a> AsRef<str> for DockerComponentLayer<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for DockerComponentLayer<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DockerConfig;

pub type DockerConfigBuilder = PlatformBuilder<DockerConfig>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DockerConfigAttribute {
    Name(String),
    Path(PathBuf),
    Layer(String),
    Config(DockerImageConfig),
}

impl DockerConfigAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }

    pub fn layer(layer: impl Into<String>) -> Self {
        Self::Layer(layer.into())
    }

    pub fn config(config: DockerImageConfig) -> Self {
        Self::Config(config)
    }
}

#[derive(ProvidesStaticType)]
pub struct DockerConfigComponentName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for DockerConfigComponentName<'a> {
    const UUID: Uuid = uuid("EB0E47B7-8E58-4BFB-B9D0-B13BA19D86DB");
}

impl<'a> AsRef<str> for DockerConfigComponentName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for DockerConfigComponentName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct DockerConfigComponentPath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for DockerConfigComponentPath<'a> {
    const UUID: Uuid = uuid("AE967684-E829-4F9E-9689-EEF6DB10D278");
}

impl<'a> AsRef<Path> for DockerConfigComponentPath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for DockerConfigComponentPath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl PlatformProvider for DockerConfig {
    type Attribute = DockerConfigAttribute;

    const NAME: &'static str = "docker.config";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for DockerConfigAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(DockerConfigComponentName(name));
            }
            Self::Path(path) => {
                container.set_attr(DockerConfigComponentPath(path));
            }
            Self::Layer(layer) => {
                container.set_attr(DockerComponentLayer(layer));
            }
            Self::Config(config) => {
                container.set_attr(DockerComponentImageConfig(config));
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DockerShadow;

pub type DockerShadowBuilder = PlatformBuilder<DockerShadow>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DockerShadowAttribute {
    Name(String),
    Path(PathBuf),
    Layer(String),
}

impl DockerShadowAttribute {
    pub fn name(name: impl Into<String>) -> Self {
        Self::Name(name.into())
    }

    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }

    pub fn layer(layer: impl Into<String>) -> Self {
        Self::Layer(layer.into())
    }
}

#[derive(ProvidesStaticType)]
pub struct DockerShadowComponentName<'a>(&'a str);
impl<'a> LoaderAttribute<'a> for DockerShadowComponentName<'a> {
    const UUID: Uuid = uuid("AF9D74D8-05B9-4FA8-A74B-EE4CC0942B03");
}

impl<'a> AsRef<str> for DockerShadowComponentName<'a> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> Deref for DockerShadowComponentName<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(ProvidesStaticType)]
pub struct DockerShadowComponentPath<'a>(&'a Path);
impl<'a> LoaderAttribute<'a> for DockerShadowComponentPath<'a> {
    const UUID: Uuid = uuid("CB8DA73A-E51D-4287-AFAF-C97753634338");
}

impl<'a> AsRef<Path> for DockerShadowComponentPath<'a> {
    fn as_ref(&self) -> &Path {
        self.0
    }
}

impl<'a> Deref for DockerShadowComponentPath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl PlatformProvider for DockerShadow {
    type Attribute = DockerShadowAttribute;

    const NAME: &'static str = "docker.shadow";
    const LOADER: PlatformComponentLoader = PlatformComponentLoader::data();
}

impl PlatformAttributeProvider for DockerShadowAttribute {
    fn apply_attribute<'a>(&'a self, container: &mut LoaderContainer<'a>) {
        match self {
            Self::Name(name) => {
                container.set_attr(DockerShadowComponentName(name));
            }
            Self::Path(path) => {
                container.set_attr(DockerShadowComponentPath(path));
            }
            Self::Layer(layer) => {
                container.set_attr(DockerComponentLayer(layer));
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // from: https://github.com/opencontainers/image-spec/blob/main/config.md#example
    const DOCKER_CONFIG_JSON: &str = r#"{
        "created": "2015-10-31T22:22:56.015925234Z",
        "author": "Alyssa P. Hacker <alyspdev@example.com>",
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "User": "alice",
            "ExposedPorts": {
                "8080/tcp": {}
            },
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "FOO=oci_is_a",
                "BAR=well_written_spec"
            ],
            "Entrypoint": [
                "/bin/my-app-binary"
            ],
            "Cmd": [
                "--foreground",
                "--config",
                "/etc/my-app.d/default.cfg"
            ],
            "Volumes": {
                "/var/job-result-data": {},
                "/var/log/my-app-logs": {}
            },
            "WorkingDir": "/home/alice",
            "Labels": {
                "com.example.project.git.url": "https://example.com/project.git",
                "com.example.project.git.commit": "45a939b2999782a3f005621a8d0f29aa387e1d6b"
            }
        },
        "rootfs": {
          "diff_ids": [
            "sha256:c6f988f4874bb0add23a778f753c65efe992244e148a1d2ec2a8b664fb66bbd1",
            "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
          ],
          "type": "layers"
        },
        "history": [
          {
            "created": "2015-10-31T22:22:54.690851953Z",
            "created_by": "/bin/sh -c #(nop) ADD file:a3bc1e842b69636f9df5256c49c5374fb4eef1e281fe3f282c65fb853ee171c5 in /"
          },
          {
            "created": "2015-10-31T22:22:55.613815829Z",
            "created_by": "/bin/sh -c #(nop) CMD [\"sh\"]",
            "empty_layer": true
          },
          {
            "created": "2015-10-31T22:22:56.329850019Z",
            "created_by": "/bin/sh -c apk add curl"
          }
        ]
    }"#;

    const DOCKER_CENTOS_CONFIG_JSON: &str = r##"{
      "architecture": "amd64",
      "config": {
        "Hostname": "",
        "Domainname": "",
        "User": "",
        "AttachStdin": false,
        "AttachStdout": false,
        "AttachStderr": false,
        "Tty": false,
        "OpenStdin": false,
        "StdinOnce": false,
        "Env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "Cmd": [
          "/bin/bash"
        ],
        "Image": "sha256:f5b050f177fd426be8fe998a8ecf3fb1858d7e26dff4080b29a327d1bd5ba422",
        "Volumes": null,
        "WorkingDir": "",
        "Entrypoint": null,
        "OnBuild": null,
        "Labels": {
          "org.label-schema.build-date": "20210915",
          "org.label-schema.license": "GPLv2",
          "org.label-schema.name": "CentOS Base Image",
          "org.label-schema.schema-version": "1.0",
          "org.label-schema.vendor": "CentOS"
        }
      },
      "container": "9bf8a9e2ddff4c0d76a587c40239679f29c863a967f23abf7a5babb6c2121bf1",
      "container_config": {
        "Hostname": "9bf8a9e2ddff",
        "Domainname": "",
        "User": "",
        "AttachStdin": false,
        "AttachStdout": false,
        "AttachStderr": false,
        "Tty": false,
        "OpenStdin": false,
        "StdinOnce": false,
        "Env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "Cmd": [
          "/bin/sh",
          "-c",
          "#(nop) ",
          "CMD [\"/bin/bash\"]"
        ],
        "Image": "sha256:f5b050f177fd426be8fe998a8ecf3fb1858d7e26dff4080b29a327d1bd5ba422",
        "Volumes": null,
        "WorkingDir": "",
        "Entrypoint": null,
        "OnBuild": null,
        "Labels": {
          "org.label-schema.build-date": "20210915",
          "org.label-schema.license": "GPLv2",
          "org.label-schema.name": "CentOS Base Image",
          "org.label-schema.schema-version": "1.0",
          "org.label-schema.vendor": "CentOS"
        }
      },
      "created": "2021-09-15T18:20:05.184694267Z",
      "docker_version": "20.10.7",
      "history": [
        {
          "created": "2021-09-15T18:20:04.026056566Z",
          "created_by": "/bin/sh -c #(nop) ADD file:805cb5e15fb6e0bb0326ca33fd2942e068863ce2a8491bb71522c652f31fb466 in / "
        },
        {
          "created": "2021-09-15T18:20:04.987853959Z",
          "created_by": "/bin/sh -c #(nop)  LABEL org.label-schema.schema-version=1.0 org.label-schema.name=CentOS Base Image org.label-schema.vendor=CentOS org.label-schema.license=GPLv2 org.label-schema.build-date=20210915",
          "empty_layer": true
        },
        {
          "created": "2021-09-15T18:20:05.184694267Z",
          "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/bash\"]",
          "empty_layer": true
        }
      ],
      "os": "linux",
      "rootfs": {
        "type": "layers",
        "diff_ids": [
          "sha256:74ddd0ec08fa43d09f32636ba91a0a3053b02cb4627c35051aff89f853606b59"
        ]
      }
    }"##;

    #[test]
    fn test_docker_image_config_deserialise() {
        // test deserialisation from official format
        let config1 = serde_json::from_str::<DockerImageConfig>(DOCKER_CONFIG_JSON).unwrap();
        let config2 = serde_json::from_str::<DockerImageConfig>(DOCKER_CENTOS_CONFIG_JSON).unwrap();

        // test roundtrip using default ser/de strategy
        let config_ser1 = serde_json::to_string_pretty(&config1).unwrap();
        let config_de1 = serde_json::from_str::<DockerImageConfig>(&config_ser1).unwrap();

        assert_eq!(config1, config_de1);

        let config_ser2 = serde_json::to_string_pretty(&config2).unwrap();
        let config_de2 = serde_json::from_str::<DockerImageConfig>(&config_ser2).unwrap();

        assert_eq!(config2, config_de2);
    }
}
