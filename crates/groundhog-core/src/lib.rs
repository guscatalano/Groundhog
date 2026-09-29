//! Platform-independent core of Groundhog: the Groundhogfile model, loading from paths, URLs
//! and zip bundles, content-addressed caching, and the resumable step engine.
//!
//! Nothing here touches the machine being configured; that is the agent's job, through the
//! [`engine::Executor`] trait.

pub mod archive;
pub mod cache;
pub mod content;
pub mod engine;
pub mod fetch;
pub mod loader;
pub mod model;
pub mod pending;
pub mod plugin;
pub mod report;
