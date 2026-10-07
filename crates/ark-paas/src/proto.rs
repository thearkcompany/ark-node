//! Protobuf message types and codecs for ark-paas workers, configurations, triggers, and telemetry.

pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/ark.paas.v1.rs"));
}

pub use v1::trigger_payload::TriggerType;
pub use v1::{ExecutionStatus, ExecutionTelemetry, TriggerPayload, WorkerConfig, WorkerManifest};
