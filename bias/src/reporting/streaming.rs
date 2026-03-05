use std::io::Write;
use std::marker::PhantomData;
use std::thread::{spawn, JoinHandle};

use crate::component::Component;
use crate::package::Package;
use crate::pipeline::property::Property;
use crate::pipeline::sink::Sink;
use crate::pipeline::source::PackageDependencyGraph;
use crate::pipeline::PipelineError;

use uuid::Uuid;

pub trait PropertyStreamTarget: Send + Sync + 'static {}

pub struct JSONL;
impl PropertyStreamTarget for JSONL {}

pub type JSONLPropertyStream = PropertyStreamSink<JSONL>;

pub struct PropertyStreamSink<T>
where
    T: PropertyStreamTarget,
{
    inner: Option<PropertyStreamSinkInner<T>>,
}

struct PropertyStreamSinkInner<T>
where
    T: PropertyStreamTarget,
{
    handle: JoinHandle<Result<(), PipelineError>>,
    properties: flume::Sender<Property>,
    _marker: PhantomData<T>,
}

impl<T> Drop for PropertyStreamSink<T>
where
    T: PropertyStreamTarget,
{
    fn drop(&mut self) {
        let _ = self.finalise();
    }
}

impl<T> PropertyStreamSink<T>
where
    T: PropertyStreamTarget,
{
    pub fn finalise(&mut self) -> Result<(), PipelineError> {
        if let Some(PropertyStreamSinkInner {
            handle, properties, ..
        }) = self.inner.take()
        {
            drop(properties); // close
            handle
                .join()
                .map_err(|_| PipelineError::io_with("cannot join on I/O thread"))??;
        }

        Ok(())
    }
}

impl PropertyStreamSink<JSONL> {
    pub fn bounded<W>(limit: usize, writer: W) -> Result<Self, PipelineError>
    where
        W: Write + Send + 'static,
    {
        let (tx, rx) = flume::bounded(limit);
        Self::new(rx, tx, writer)
    }

    pub fn unbounded<W>(writer: W) -> Result<Self, PipelineError>
    where
        W: Write + Send + 'static,
    {
        let (tx, rx) = flume::unbounded();
        Self::new(rx, tx, writer)
    }

    fn new<W>(
        rx: flume::Receiver<Property>,
        tx: flume::Sender<Property>,
        mut writer: W,
    ) -> Result<Self, PipelineError>
    where
        W: Write + Send + 'static,
    {
        let handle = spawn(move || -> Result<(), PipelineError> {
            let properties = rx;

            while let Ok(property) = properties.recv().map_err(PipelineError::io) {
                serde_json::to_writer(&mut writer, &property).map_err(PipelineError::io)?;
                writer.write(b"\n").map_err(PipelineError::io)?;
            }

            Ok(())
        });

        Ok(Self {
            inner: Some(PropertyStreamSinkInner {
                handle,
                properties: tx,
                _marker: PhantomData,
            }),
        })
    }
}

#[async_trait::async_trait]
impl<T> Sink for PropertyStreamSink<T>
where
    T: PropertyStreamTarget,
{
    async fn push_package(
        &self,
        _package: Package,
        _dependencies: PackageDependencyGraph,
    ) -> Result<(), PipelineError> {
        Ok(())
    }

    async fn push_component(&self, _pid: Uuid, _component: Component) -> Result<(), PipelineError> {
        Ok(())
    }

    async fn push_component_property(
        &self,
        _pid: Uuid,
        _cid: Uuid,
        property: Property,
    ) -> Result<(), PipelineError> {
        self.inner
            .as_ref()
            .ok_or_else(|| PipelineError::io_with("attempt to send property to closed channel"))?
            .properties
            .send_async(property)
            .await
            .map_err(PipelineError::io)?;
        Ok(())
    }

    async fn push_package_property(
        &self,
        _pid: Uuid,
        property: Property,
    ) -> Result<(), PipelineError> {
        self.inner
            .as_ref()
            .ok_or_else(|| PipelineError::io_with("attempt to send property to closed channel"))?
            .properties
            .send_async(property)
            .await
            .map_err(PipelineError::io)?;
        Ok(())
    }
}

#[derive(serde::Serialize)]
#[serde(tag = "entity", rename_all = "kebab-case")]
enum ReportEntity {
    Package(Package),
    Component(Component),
    Property {
        package_id: Uuid,
        target_id: Uuid,
        payload: Property,
    },
}

pub trait EntityStreamTarget: Send + Sync + 'static {}

impl EntityStreamTarget for JSONL {}

pub type JSONLEntityStream = EntityStreamSink<JSONL>;

pub struct EntityStreamSink<T>
where
    T: EntityStreamTarget,
{
    inner: Option<EntityStreamSinkInner<T>>,
}

struct EntityStreamSinkInner<T>
where
    T: EntityStreamTarget,
{
    handle: JoinHandle<Result<(), PipelineError>>,
    entities: flume::Sender<ReportEntity>,
    _marker: PhantomData<T>,
}

impl<T> Drop for EntityStreamSink<T>
where
    T: EntityStreamTarget,
{
    fn drop(&mut self) {
        let _ = self.finalise();
    }
}

impl<T> EntityStreamSink<T>
where
    T: EntityStreamTarget,
{
    pub fn finalise(&mut self) -> Result<(), PipelineError> {
        if let Some(EntityStreamSinkInner {
            handle, entities, ..
        }) = self.inner.take()
        {
            drop(entities); // close
            handle
                .join()
                .map_err(|_| PipelineError::io_with("cannot join on I/O thread"))??;
        }

        Ok(())
    }
}

impl EntityStreamSink<JSONL> {
    pub fn bounded<W>(limit: usize, writer: W) -> Result<Self, PipelineError>
    where
        W: Write + Send + 'static,
    {
        Self::bounded_with(limit, writer, false)
    }

    pub fn bounded_with<W>(limit: usize, writer: W, compress: bool) -> Result<Self, PipelineError>
    where
        W: Write + Send + 'static,
    {
        let (tx, rx) = flume::bounded(limit);
        Self::new(rx, tx, writer, compress)
    }

    pub fn unbounded<W>(writer: W) -> Result<Self, PipelineError>
    where
        W: Write + Send + 'static,
    {
        Self::unbounded_with(writer, false)
    }

    pub fn unbounded_with<W>(writer: W, compress: bool) -> Result<Self, PipelineError>
    where
        W: Write + Send + 'static,
    {
        let (tx, rx) = flume::unbounded();
        Self::new(rx, tx, writer, compress)
    }

    fn spawn_handler<W>(
        mut writer: W,
        entities: flume::Receiver<ReportEntity>,
    ) -> JoinHandle<Result<(), PipelineError>>
    where
        W: Write + Send + 'static,
    {
        spawn(move || -> Result<(), PipelineError> {
            while let Ok(entity) = entities.recv().map_err(PipelineError::io) {
                serde_json::to_writer(&mut writer, &entity).map_err(PipelineError::io)?;
                writer.write(b"\n").map_err(PipelineError::io)?;
            }

            Ok(())
        })
    }

    fn new<W>(
        rx: flume::Receiver<ReportEntity>,
        tx: flume::Sender<ReportEntity>,
        writer: W,
        compress: bool,
    ) -> Result<Self, PipelineError>
    where
        W: Write + Send + 'static,
    {
        let handle = if compress {
            let writer = zstd::stream::Encoder::new(writer, 0).map_err(PipelineError::io)?;
            Self::spawn_handler(writer.auto_finish(), rx)
        } else {
            Self::spawn_handler(writer, rx)
        };

        Ok(Self {
            inner: Some(EntityStreamSinkInner {
                handle,
                entities: tx,
                _marker: PhantomData,
            }),
        })
    }
}

#[async_trait::async_trait]
impl<T> Sink for EntityStreamSink<T>
where
    T: EntityStreamTarget,
{
    async fn push_package(
        &self,
        package: Package,
        _dependencies: PackageDependencyGraph,
    ) -> Result<(), PipelineError> {
        self.inner
            .as_ref()
            .ok_or_else(|| PipelineError::io_with("attempt to send package to closed channel"))?
            .entities
            .send_async(ReportEntity::Package(package))
            .await
            .map_err(PipelineError::io)?;
        Ok(())
    }

    async fn push_component(&self, _pid: Uuid, component: Component) -> Result<(), PipelineError> {
        self.inner
            .as_ref()
            .ok_or_else(|| PipelineError::io_with("attempt to send component to closed channel"))?
            .entities
            .send_async(ReportEntity::Component(component))
            .await
            .map_err(PipelineError::io)?;
        Ok(())
    }

    async fn push_component_property(
        &self,
        pid: Uuid,
        cid: Uuid,
        property: Property,
    ) -> Result<(), PipelineError> {
        self.inner
            .as_ref()
            .ok_or_else(|| PipelineError::io_with("attempt to send property to closed channel"))?
            .entities
            .send_async(ReportEntity::Property {
                package_id: pid,
                target_id: cid,
                payload: property,
            })
            .await
            .map_err(PipelineError::io)?;
        Ok(())
    }

    async fn push_package_property(
        &self,
        pid: Uuid,
        property: Property,
    ) -> Result<(), PipelineError> {
        self.inner
            .as_ref()
            .ok_or_else(|| PipelineError::io_with("attempt to send property to closed channel"))?
            .entities
            .send_async(ReportEntity::Property {
                package_id: pid,
                target_id: pid,
                payload: property,
            })
            .await
            .map_err(PipelineError::io)?;
        Ok(())
    }
}
