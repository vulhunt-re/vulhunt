use bias::platform::common::PlatformAttributeMap;

use bias_vulhunt_engine::{SignatureEntry, SignatureRange, SignatureVersion};

use serde_json::{Map, Value};
use tonic::Status;

use crate::proto;

pub(crate) fn proto_value_to_json(v: prost_wkt_types::Value) -> Value {
    match v.kind {
        Some(prost_wkt_types::value::Kind::NullValue(_)) => Value::Null,
        Some(prost_wkt_types::value::Kind::NumberValue(n)) => {
            if n.fract() == 0f64 {
                Value::Number(serde_json::Number::from(n as i64))
            } else {
                serde_json::Number::from_f64(n)
                    .map(Value::Number)
                    .unwrap_or(Value::Null)
            }
        }
        Some(prost_wkt_types::value::Kind::StringValue(s)) => Value::String(s),
        Some(prost_wkt_types::value::Kind::BoolValue(b)) => Value::Bool(b),
        Some(prost_wkt_types::value::Kind::StructValue(s)) => {
            let map = s
                .fields
                .into_iter()
                .map(|(k, v)| (k, proto_value_to_json(v)))
                .collect();
            Value::Object(map)
        }
        Some(prost_wkt_types::value::Kind::ListValue(l)) => {
            let values = l.values.into_iter().map(proto_value_to_json).collect();
            Value::Array(values)
        }
        None => Value::Null,
    }
}

pub(crate) fn proto_struct_to_attrs(s: prost_wkt_types::Struct) -> PlatformAttributeMap {
    s.fields
        .into_iter()
        .map(|(k, v)| (k, proto_value_to_json(v)))
        .collect()
}

pub(crate) fn json_to_proto_value(v: Value) -> prost_wkt_types::Value {
    let kind = match v {
        Value::Null => prost_wkt_types::value::Kind::NullValue(0),
        Value::Bool(b) => prost_wkt_types::value::Kind::BoolValue(b),
        Value::Number(n) => prost_wkt_types::value::Kind::NumberValue(n.as_f64().unwrap_or(0f64)),
        Value::String(s) => prost_wkt_types::value::Kind::StringValue(s),
        Value::Array(arr) => prost_wkt_types::value::Kind::ListValue(prost_wkt_types::ListValue {
            values: arr.into_iter().map(json_to_proto_value).collect(),
        }),
        Value::Object(map) => prost_wkt_types::value::Kind::StructValue(attrs_to_proto_struct(map)),
    };
    prost_wkt_types::Value { kind: Some(kind) }
}

pub(crate) fn attrs_to_proto_struct(map: Map<String, Value>) -> prost_wkt_types::Struct {
    prost_wkt_types::Struct {
        fields: map
            .into_iter()
            .map(|(k, v)| (k, json_to_proto_value(v)))
            .collect(),
    }
}

impl TryFrom<proto::SignatureEntry> for SignatureEntry {
    type Error = Status;

    fn try_from(entry: proto::SignatureEntry) -> Result<Self, Status> {
        match entry.spec {
            Some(proto::signature_entry::Spec::Range(r)) => Ok(SignatureEntry::Range(
                SignatureRange::new(r.project, r.from, r.to),
            )),
            Some(proto::signature_entry::Spec::Version(v)) => Ok(SignatureEntry::Version(
                SignatureVersion::new(v.project, v.version),
            )),
            Some(proto::signature_entry::Spec::File(f)) => Ok(SignatureEntry::File(f)),
            None => Err(Status::invalid_argument("signature entry must have a spec")),
        }
    }
}

impl From<SignatureEntry> for proto::SignatureEntry {
    fn from(entry: SignatureEntry) -> Self {
        let spec = match entry {
            SignatureEntry::Range(r) => {
                proto::signature_entry::Spec::Range(proto::SignatureRange {
                    project: r.project().to_owned(),
                    from: r.from().map(String::from),
                    to: r.to().map(String::from),
                })
            }
            SignatureEntry::Version(v) => {
                proto::signature_entry::Spec::Version(proto::SignatureVersion {
                    project: v.project().to_owned(),
                    version: v.version().to_owned(),
                })
            }
            SignatureEntry::File(f) => proto::signature_entry::Spec::File(f),
        };
        proto::SignatureEntry { spec: Some(spec) }
    }
}
