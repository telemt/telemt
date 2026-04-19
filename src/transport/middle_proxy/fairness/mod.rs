//! Backpressure-driven fairness control for ME reader routing.
//!
//! This module keeps fairness decisions worker-local:
//! each reader loop owns one scheduler instance and mutates it without locks.

mod model;
mod pressure;
mod scheduler;

pub(crate) use model::PressureState;
pub(crate) use model::{AdmissionDecision, DispatchAction, DispatchFeedback, SchedulerDecision};
pub(crate) use scheduler::{WorkerFairnessConfig, WorkerFairnessSnapshot, WorkerFairnessState};
