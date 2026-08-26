use bias_vulhunt_engine::{SignatureEntry, VulHuntProjectErrorKind};

use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::convert::proto_struct_to_attrs;
use crate::proto;
use super::session::{VulHuntHandler, VulHuntHandlerError};

impl From<VulHuntHandlerError> for Status {
    fn from(err: VulHuntHandlerError) -> Self {
        match &err {
            VulHuntHandlerError::SessionNotFound(_) => Status::not_found(err.to_string()),
            VulHuntHandlerError::Project(e) => match e.kind() {
                VulHuntProjectErrorKind::UnknownFunction(_) => Status::not_found(err.to_string()),
                VulHuntProjectErrorKind::InvalidFunctionSymbol(_)
                | VulHuntProjectErrorKind::DuplicateFunctionSymbol(_) => {
                    Status::invalid_argument(err.to_string())
                }
                VulHuntProjectErrorKind::ReadOrParse | VulHuntProjectErrorKind::Unsupported => {
                    Status::failed_precondition(err.to_string())
                }
                _ => Status::internal(err.to_string()),
            },
            VulHuntHandlerError::Join(_) => Status::internal(err.to_string()),
        }
    }
}

fn parse_session_id(session_id: &str) -> Result<Uuid, Status> {
    session_id
        .parse::<Uuid>()
        .map_err(|e| Status::invalid_argument(format!("invalid session_id: {e}")))
}

#[tonic::async_trait]
impl proto::vul_hunt_server::VulHunt for VulHuntHandler {
    async fn open_project(
        &self,
        request: Request<proto::OpenProjectRequest>,
    ) -> Result<Response<proto::OpenProjectResponse>, Status> {
        let req = request.into_inner();
        let attributes = req.attributes.map(proto_struct_to_attrs);

        let session_id = self.open_project(req.path, attributes).await?;

        Ok(Response::new(proto::OpenProjectResponse {
            session_id: session_id.to_string(),
        }))
    }

    async fn close_project(
        &self,
        request: Request<proto::CloseProjectRequest>,
    ) -> Result<Response<proto::CloseProjectResponse>, Status> {
        let req = request.into_inner();
        let session_id = parse_session_id(&req.session_id)?;

        self.close_session(session_id).await?;

        Ok(Response::new(proto::CloseProjectResponse::default()))
    }

    async fn list_sessions(
        &self,
        _request: Request<proto::ListSessionsRequest>,
    ) -> Result<Response<proto::ListSessionsResponse>, Status> {
        let sessions = VulHuntHandler::list_sessions(self).await;

        let system_now = std::time::SystemTime::now();
        let instant_now = std::time::Instant::now();

        let sessions = sessions
            .into_iter()
            .map(|s| {
                let created_elapsed = instant_now.duration_since(s.created_at());
                let accessed_elapsed = instant_now.duration_since(s.last_accessed_at());

                proto::SessionInfo {
                    session_id: s.session_id().to_string(),
                    path: s.path().display().to_string(),
                    created_at: Some(prost_wkt_types::Timestamp::from(
                        system_now - created_elapsed,
                    )),
                    last_accessed_at: Some(prost_wkt_types::Timestamp::from(
                        system_now - accessed_elapsed,
                    )),
                }
            })
            .collect();

        Ok(Response::new(proto::ListSessionsResponse { sessions }))
    }

    async fn query_project(
        &self,
        request: Request<proto::QueryProjectRequest>,
    ) -> Result<Response<proto::QueryProjectResponse>, Status> {
        let req = request.into_inner();
        let session_id = parse_session_id(&req.session_id)?;
        let state = self.get_session(session_id).await?;

        let script = req.script;

        let json_value = tokio::task::spawn_blocking(move || {
            let mut state = state.blocking_write();
            state.project_mut().query(&script)
        })
        .await
        .map_err(VulHuntHandlerError::from)?
        .map_err(VulHuntHandlerError::from)?;

        let result = serde_json::from_value(json_value)
            .map_err(|e| Status::internal(format!("failed to convert query result: {e}")))?;

        Ok(Response::new(proto::QueryProjectResponse {
            result: Some(result),
        }))
    }

    async fn update_function_name(
        &self,
        request: Request<proto::UpdateFunctionNameRequest>,
    ) -> Result<Response<proto::UpdateFunctionNameResponse>, Status> {
        let req = request.into_inner();
        let session_id = parse_session_id(&req.session_id)?;
        let state = self.get_session(session_id).await?;

        let function = req.function;
        let new_name = req.new_name;

        tokio::task::spawn_blocking(move || {
            let mut state = state.blocking_write();
            state
                .project_mut()
                .update_function_name(&function, &new_name)
        })
        .await
        .map_err(VulHuntHandlerError::from)?
        .map_err(VulHuntHandlerError::from)?;

        Ok(Response::new(proto::UpdateFunctionNameResponse::default()))
    }

    async fn set_function_notes(
        &self,
        request: Request<proto::SetFunctionNotesRequest>,
    ) -> Result<Response<proto::SetFunctionNotesResponse>, Status> {
        let req = request.into_inner();
        let session_id = parse_session_id(&req.session_id)?;
        let state = self.get_session(session_id).await?;

        let function = req.function;
        let notes = req.notes;

        tokio::task::spawn_blocking(move || {
            let mut state = state.blocking_write();
            state.project_mut().set_function_notes(&function, notes)
        })
        .await
        .map_err(VulHuntHandlerError::from)?
        .map_err(VulHuntHandlerError::from)?;

        Ok(Response::new(proto::SetFunctionNotesResponse::default()))
    }

    async fn get_function_notes(
        &self,
        request: Request<proto::GetFunctionNotesRequest>,
    ) -> Result<Response<proto::GetFunctionNotesResponse>, Status> {
        let req = request.into_inner();
        let session_id = parse_session_id(&req.session_id)?;
        let state = self.get_session(session_id).await?;

        let function = req.function;

        let notes = tokio::task::spawn_blocking(move || {
            let state = state.blocking_read();
            state.project().function_notes(&function).map(String::from)
        })
        .await
        .map_err(VulHuntHandlerError::from)?;

        Ok(Response::new(proto::GetFunctionNotesResponse { notes }))
    }

    async fn load_signatures(
        &self,
        request: Request<proto::LoadSignaturesRequest>,
    ) -> Result<Response<proto::LoadSignaturesResponse>, Status> {
        let req = request.into_inner();
        let session_id = parse_session_id(&req.session_id)?;
        let state = self.get_session(session_id).await?;

        let entries = req
            .signatures
            .into_iter()
            .map(SignatureEntry::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let result = tokio::task::spawn_blocking(move || {
            let mut state = state.blocking_write();
            state.project_mut().load_signatures(entries)
        })
        .await
        .map_err(VulHuntHandlerError::from)?
        .map_err(VulHuntHandlerError::from)?;

        Ok(Response::new(proto::LoadSignaturesResponse {
            loaded_files: result.loaded_files().to_vec(),
            matched_functions: result.matched_functions() as u64,
        }))
    }

    async fn load_types(
        &self,
        request: Request<proto::LoadTypesRequest>,
    ) -> Result<Response<proto::LoadTypesResponse>, Status> {
        let req = request.into_inner();
        let session_id = parse_session_id(&req.session_id)?;
        let state = self.get_session(session_id).await?;

        let types = req.types;

        let result = tokio::task::spawn_blocking(move || {
            let mut state = state.blocking_write();
            state.project_mut().load_types(&types)
        })
        .await
        .map_err(VulHuntHandlerError::from)?
        .map_err(VulHuntHandlerError::from)?;

        Ok(Response::new(proto::LoadTypesResponse {
            type_library: result.type_library().to_owned(),
            imported_types: result.imported_types() as u64,
            matched_functions: result.matched_functions() as u64,
        }))
    }
}
