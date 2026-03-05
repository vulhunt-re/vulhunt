use crate::platform::docker::DockerImageConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DockerConfigAttributes {
    #[serde(default)]
    magic_string: String,
    #[serde(default)]
    extension: String,
    #[serde(default)]
    layer: String,
    image_config: DockerImageConfig,
}

impl DockerConfigAttributes {
    pub fn new(
        magic_string: impl Into<String>,
        extension: impl Into<String>,
        layer: impl Into<String>,
        image_config: DockerImageConfig,
    ) -> Self {
        Self {
            magic_string: magic_string.into(),
            extension: extension.into(),
            layer: layer.into(),
            image_config,
        }
    }

    pub fn magic_string(&self) -> &str {
        &self.magic_string
    }

    pub fn extension(&self) -> &str {
        &self.extension
    }

    pub fn layer(&self) -> &str {
        &self.layer
    }

    pub fn image_config(&self) -> &DockerImageConfig {
        &self.image_config
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DockerShadowAttributes {
    #[serde(default)]
    magic_string: String,
    #[serde(default)]
    extension: String,
    #[serde(default)]
    layer: String,
}

impl DockerShadowAttributes {
    pub fn new(
        magic_string: impl Into<String>,
        extension: impl Into<String>,
        layer: impl Into<String>,
    ) -> Self {
        Self {
            magic_string: magic_string.into(),
            extension: extension.into(),
            layer: layer.into(),
        }
    }

    pub fn magic_string(&self) -> &str {
        &self.magic_string
    }

    pub fn extension(&self) -> &str {
        &self.extension
    }

    pub fn layer(&self) -> &str {
        &self.layer
    }
}
