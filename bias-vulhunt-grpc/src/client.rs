use std::path::Path;

use bias_core::ir::Address;
use bias_vulhunt_engine::SignatureEntry;

use serde_json::{Map, Value};
use thiserror::Error;
use tonic::transport::{Channel, Endpoint};

use crate::convert::{attrs_to_proto_struct, proto_value_to_json};
use crate::proto;

pub trait FunctionQuery {
    fn into_function_query(self) -> String;
}

impl FunctionQuery for String {
    fn into_function_query(self) -> String {
        self
    }
}

impl FunctionQuery for &str {
    fn into_function_query(self) -> String {
        self.to_owned()
    }
}

impl FunctionQuery for u64 {
    fn into_function_query(self) -> String {
        format!("0x{self:x}")
    }
}

impl FunctionQuery for Address {
    fn into_function_query(self) -> String {
        self.to_string()
    }
}

#[derive(Debug, Error)]
pub enum VulHuntClientError {
    #[error("no active session (call open_project first)")]
    NoSession,
    #[error("gRPC transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("RPC failed: {0}")]
    Status(#[from] tonic::Status),
}

pub struct VulHuntClient {
    inner: proto::vul_hunt_client::VulHuntClient<Channel>,
    session_id: Option<String>,
}

impl VulHuntClient {
    pub async fn new(
        endpoint: impl TryInto<Endpoint, Error = tonic::transport::Error>,
    ) -> Result<Self, VulHuntClientError> {
        Self::new_with(endpoint, None).await
    }

    pub async fn new_with(
        endpoint: impl TryInto<Endpoint, Error = tonic::transport::Error>,
        session_id: impl Into<Option<String>>,
    ) -> Result<Self, VulHuntClientError> {
        let inner = proto::vul_hunt_client::VulHuntClient::connect(endpoint).await?;
        Ok(Self {
            inner,
            session_id: session_id.into(),
        })
    }

    #[deprecated(note = "use `new` instead")]
    pub async fn connect(
        endpoint: impl TryInto<Endpoint, Error = tonic::transport::Error>,
    ) -> Result<Self, VulHuntClientError> {
        Self::new(endpoint).await
    }

    fn require_session(&self) -> Result<&str, VulHuntClientError> {
        self.session_id
            .as_deref()
            .ok_or(VulHuntClientError::NoSession)
    }

    pub async fn open_project(
        &mut self,
        path: impl AsRef<Path>,
        attributes: Option<Map<String, Value>>,
    ) -> Result<String, VulHuntClientError> {
        let response = self
            .inner
            .open_project(proto::OpenProjectRequest {
                path: path.as_ref().display().to_string(),
                attributes: attributes.map(attrs_to_proto_struct),
            })
            .await?
            .into_inner();

        self.session_id = Some(response.session_id.clone());
        Ok(response.session_id)
    }

    pub async fn close_project(&mut self) -> Result<(), VulHuntClientError> {
        let session_id = self.require_session()?.to_owned();
        self.inner
            .close_project(proto::CloseProjectRequest { session_id })
            .await?;
        self.session_id = None;
        Ok(())
    }

    pub async fn list_sessions(&mut self) -> Result<Vec<proto::SessionInfo>, VulHuntClientError> {
        let response = self
            .inner
            .list_sessions(proto::ListSessionsRequest {})
            .await?
            .into_inner();
        Ok(response.sessions)
    }

    pub async fn query_project(
        &mut self,
        script: impl Into<String>,
    ) -> Result<Value, VulHuntClientError> {
        let session_id = self.require_session()?.to_owned();
        let response = self
            .inner
            .query_project(proto::QueryProjectRequest {
                session_id,
                script: script.into(),
            })
            .await?
            .into_inner();

        Ok(response
            .result
            .map(proto_value_to_json)
            .unwrap_or(Value::Null))
    }

    pub async fn update_function_name(
        &mut self,
        function: impl FunctionQuery,
        new_name: impl Into<String>,
    ) -> Result<(), VulHuntClientError> {
        let session_id = self.require_session()?.to_owned();
        self.inner
            .update_function_name(proto::UpdateFunctionNameRequest {
                session_id,
                function: function.into_function_query(),
                new_name: new_name.into(),
            })
            .await?;
        Ok(())
    }

    pub async fn set_function_notes(
        &mut self,
        function: impl FunctionQuery,
        notes: impl Into<String>,
    ) -> Result<(), VulHuntClientError> {
        let session_id = self.require_session()?.to_owned();
        self.inner
            .set_function_notes(proto::SetFunctionNotesRequest {
                session_id,
                function: function.into_function_query(),
                notes: notes.into(),
            })
            .await?;
        Ok(())
    }

    pub async fn get_function_notes(
        &mut self,
        function: impl FunctionQuery,
    ) -> Result<Option<String>, VulHuntClientError> {
        let session_id = self.require_session()?.to_owned();
        let response = self
            .inner
            .get_function_notes(proto::GetFunctionNotesRequest {
                session_id,
                function: function.into_function_query(),
            })
            .await?
            .into_inner();
        Ok(response.notes)
    }

    pub async fn load_signatures(
        &mut self,
        signatures: impl IntoIterator<Item = SignatureEntry>,
    ) -> Result<proto::LoadSignaturesResponse, VulHuntClientError> {
        let session_id = self.require_session()?.to_owned();
        let response = self
            .inner
            .load_signatures(proto::LoadSignaturesRequest {
                session_id,
                signatures: signatures.into_iter().map(Into::into).collect(),
            })
            .await?
            .into_inner();
        Ok(response)
    }

    pub async fn load_types(
        &mut self,
        types: impl Into<String>,
    ) -> Result<proto::LoadTypesResponse, VulHuntClientError> {
        let session_id = self.require_session()?.to_owned();
        let response = self
            .inner
            .load_types(proto::LoadTypesRequest {
                session_id,
                types: types.into(),
            })
            .await?
            .into_inner();
        Ok(response)
    }
}
