//! Rate Limit Agent - Token bucket rate limiting for Zentinel
//!
//! This agent provides distributed rate limiting using token bucket algorithm
//! with support for multiple rate limit keys and configurable limits.
//!
//! Supports Protocol v2 with:
//! - Capability negotiation
//! - Health reporting
//! - Metrics export
//! - Configuration push
//! - gRPC and UDS transports

#![allow(dead_code)]

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use nonzero_ext::nonzero;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, CounterMetric, DrainReason,
    GaugeMetric, GrpcAgentServerV2, HealthConfig, HealthStatus, LoadMetrics, MetricsReport,
    ShutdownReason, UdsAgentServerV2,
};
use zentinel_agent_protocol::{
    AgentResponse, AuditMetadata, Decision, EventType, HeaderOp, RequestHeadersEvent,
};

/// Rate limit agent command-line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Unix socket path to listen on
    #[arg(
        short,
        long,
        env = "RATELIMIT_AGENT_SOCKET",
        default_value = "/tmp/ratelimit-agent.sock"
    )]
    socket: PathBuf,

    /// gRPC address to listen on (e.g., "0.0.0.0:50051")
    /// If provided, uses gRPC transport instead of UDS
    #[arg(long, env = "RATELIMIT_AGENT_GRPC_ADDRESS")]
    grpc_address: Option<String>,

    /// Configuration file path
    #[arg(short, long, env = "RATELIMIT_AGENT_CONFIG")]
    config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, env = "RATELIMIT_AGENT_LOG_LEVEL", default_value = "info")]
    log_level: String,

    /// Default requests per second limit
    #[arg(long, env = "RATELIMIT_AGENT_DEFAULT_RPS", default_value = "100")]
    default_rps: u32,

    /// Default burst size
    #[arg(long, env = "RATELIMIT_AGENT_DEFAULT_BURST", default_value = "200")]
    default_burst: u32,

    /// Enable dry-run mode (log but don't block)
    #[arg(long, env = "RATELIMIT_AGENT_DRY_RUN")]
    dry_run: bool,

    /// Cleanup interval for expired rate limiters (seconds)
    #[arg(long, env = "RATELIMIT_AGENT_CLEANUP_INTERVAL", default_value = "60")]
    cleanup_interval: u64,
}

/// Rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RateLimitConfig {
    /// Rate limit rules
    #[serde(default)]
    rules: Vec<RateLimitRule>,
    /// Default rule if no specific rule matches
    default: RateLimitRule,
    /// Enable dry-run mode
    #[serde(default)]
    dry_run: bool,
}

/// Individual rate limit rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RateLimitRule {
    /// Rule name/ID
    name: String,
    /// Rate limit key type
    key: RateLimitKey,
    /// Requests per second
    requests_per_second: u32,
    /// Burst size
    burst: u32,
    /// Match conditions
    #[serde(default)]
    conditions: Vec<MatchCondition>,
    /// Custom response message when rate limited
    #[serde(default)]
    message: Option<String>,
    /// Custom status code (default 429)
    #[serde(default)]
    status_code: Option<u16>,
}

/// Rate limit key types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RateLimitKey {
    /// Rate limit by client IP
    ClientIp,
    /// Rate limit by header value
    Header(String),
    /// Rate limit by path
    Path,
    /// Rate limit by method
    Method,
    /// Global rate limit (all requests)
    Global,
    /// Composite key
    Composite(Vec<RateLimitKey>),
}

/// Match conditions for applying rules
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MatchCondition {
    /// Match path prefix
    PathPrefix(String),
    /// Match exact path
    Path(String),
    /// Match header presence
    Header { name: String, value: Option<String> },
    /// Match method
    Method(Vec<String>),
}

/// Rate limiter entry
struct RateLimiterEntry {
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    last_used: Instant,
    rule_name: String,
}

/// Rate limit agent implementation
#[derive(Clone)]
struct RateLimitAgent {
    /// Configuration
    config: Arc<RwLock<RateLimitConfig>>,
    /// Configuration version
    config_version: Arc<RwLock<Option<String>>>,
    /// Rate limiters by key
    limiters: Arc<DashMap<String, RateLimiterEntry>>,
    /// Request counter
    request_count: Arc<AtomicU64>,
    /// Rate limited counter
    limited_count: Arc<AtomicU64>,
    /// Metrics
    metrics: Arc<RateLimitMetrics>,
    /// Draining flag
    draining: Arc<RwLock<bool>>,
}

/// Rate limit metrics
struct RateLimitMetrics {
    requests_total: AtomicU64,
    requests_allowed: AtomicU64,
    requests_limited: AtomicU64,
    active_limiters: std::sync::atomic::AtomicUsize,
}

impl RateLimitAgent {
    /// Create new rate limit agent
    fn new(config: RateLimitConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            config_version: Arc::new(RwLock::new(None)),
            limiters: Arc::new(DashMap::new()),
            request_count: Arc::new(AtomicU64::new(0)),
            limited_count: Arc::new(AtomicU64::new(0)),
            metrics: Arc::new(RateLimitMetrics {
                requests_total: AtomicU64::new(0),
                requests_allowed: AtomicU64::new(0),
                requests_limited: AtomicU64::new(0),
                active_limiters: std::sync::atomic::AtomicUsize::new(0),
            }),
            draining: Arc::new(RwLock::new(false)),
        }
    }

    /// Find matching rule for request
    fn find_matching_rule(&self, event: &RequestHeadersEvent) -> RateLimitRule {
        let config = self.config.read();

        for rule in &config.rules {
            if self.matches_conditions(&rule.conditions, event) {
                return rule.clone();
            }
        }

        config.default.clone()
    }

    /// Check if conditions match
    fn matches_conditions(
        &self,
        conditions: &[MatchCondition],
        event: &RequestHeadersEvent,
    ) -> bool {
        if conditions.is_empty() {
            return true;
        }

        conditions.iter().all(|condition| match condition {
            MatchCondition::PathPrefix(prefix) => event.uri.starts_with(prefix),
            MatchCondition::Path(path) => event.uri == *path,
            MatchCondition::Header { name, value } => {
                if let Some(header_values) = event.headers.get(name) {
                    if let Some(expected) = value {
                        header_values.iter().any(|v| v == expected)
                    } else {
                        true // Just check presence
                    }
                } else {
                    false
                }
            }
            MatchCondition::Method(methods) => methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&event.method)),
        })
    }

    /// Generate rate limit key
    fn generate_key(&self, key_type: &RateLimitKey, event: &RequestHeadersEvent) -> String {
        match key_type {
            RateLimitKey::ClientIp => event.metadata.client_ip.clone(),
            RateLimitKey::Header(name) => event
                .headers
                .get(name)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| format!("unknown_{}", name)),
            RateLimitKey::Path => event.uri.clone(),
            RateLimitKey::Method => event.method.clone(),
            RateLimitKey::Global => "global".to_string(),
            RateLimitKey::Composite(keys) => keys
                .iter()
                .map(|k| self.generate_key(k, event))
                .collect::<Vec<_>>()
                .join(":"),
        }
    }

    /// Get or create rate limiter
    fn get_or_create_limiter(
        &self,
        key: String,
        rule: &RateLimitRule,
    ) -> Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>> {
        if let Some(entry) = self.limiters.get(&key) {
            entry.limiter.clone()
        } else {
            // Create new limiter
            let quota = Quota::per_second(
                NonZeroU32::new(rule.requests_per_second).unwrap_or(nonzero!(100u32)),
            );

            let limiter = Arc::new(RateLimiter::direct_with_clock(
                quota,
                &DefaultClock::default(),
            ));

            let entry = RateLimiterEntry {
                limiter: limiter.clone(),
                last_used: Instant::now(),
                rule_name: rule.name.clone(),
            };

            self.limiters.insert(key, entry);
            self.metrics.active_limiters.fetch_add(1, Ordering::Relaxed);

            limiter
        }
    }

    /// Clean up expired limiters
    async fn cleanup_expired_limiters(&self, max_age: Duration) {
        let now = Instant::now();
        let mut expired = Vec::new();

        // Find expired entries
        for entry in self.limiters.iter() {
            if now.duration_since(entry.last_used) > max_age {
                expired.push(entry.key().clone());
            }
        }

        // Remove expired entries
        let expired_count = expired.len();
        for key in expired {
            self.limiters.remove(&key);
            self.metrics.active_limiters.fetch_sub(1, Ordering::Relaxed);
        }

        debug!("Cleaned up {} expired rate limiters", expired_count);
    }
}

#[async_trait]
impl AgentHandlerV2 for RateLimitAgent {
    /// Return agent capabilities for v2 protocol handshake
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            protocol_version: 2,
            agent_id: "ratelimit-agent".to_string(),
            name: "Zentinel Rate Limit Agent".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            supported_events: vec![EventType::RequestHeaders, EventType::Configure],
            features: AgentFeatures {
                streaming_body: false,
                websocket: false,
                guardrails: false,
                config_push: true,
                metrics_export: true,
                concurrent_requests: 1000,
                cancellation: true,
                flow_control: true,
                health_reporting: true,
            },
            limits: AgentLimits {
                max_body_size: 0, // We don't inspect bodies
                max_concurrency: 1000,
                preferred_chunk_size: 0,
                max_memory: None,
                max_processing_time_ms: Some(100), // Rate limiting should be fast
            },
            health: HealthConfig {
                report_interval_ms: 10_000,
                include_load_metrics: true,
                include_resource_metrics: false,
            },
        }
    }

    /// Handle configuration updates
    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        info!(
            version = ?version,
            "Received configuration event"
        );

        // Parse the configuration from JSON
        match serde_json::from_value::<RateLimitConfig>(config) {
            Ok(new_config) => {
                info!(
                    rules = new_config.rules.len(),
                    default_rps = new_config.default.requests_per_second,
                    dry_run = new_config.dry_run,
                    "Applying new rate limit configuration"
                );

                // Update the configuration
                {
                    let mut config_guard = self.config.write();
                    *config_guard = new_config;
                }

                // Update version
                {
                    let mut version_guard = self.config_version.write();
                    *version_guard = version;
                }

                // Clear existing rate limiters to apply new rules
                self.limiters.clear();
                self.metrics.active_limiters.store(0, Ordering::Relaxed);

                debug!("Configuration updated successfully");
                true
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to parse configuration, keeping existing config"
                );
                false
            }
        }
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        process_request_headers(self, event).await
    }

    /// Return current health status
    fn health_status(&self) -> HealthStatus {
        let is_draining = *self.draining.read();

        if is_draining {
            HealthStatus {
                agent_id: "ratelimit-agent".to_string(),
                state: zentinel_agent_protocol::v2::HealthState::Draining { eta_ms: None },
                message: Some("Agent is draining".to_string()),
                load: Some(self.get_load_metrics()),
                resources: None,
                valid_until_ms: None,
                timestamp_ms: now_ms(),
            }
        } else {
            HealthStatus::healthy("ratelimit-agent").with_load(self.get_load_metrics())
        }
    }

    /// Return current metrics report
    fn metrics_report(&self) -> Option<MetricsReport> {
        let requests_total = self.metrics.requests_total.load(Ordering::Relaxed);
        let requests_allowed = self.metrics.requests_allowed.load(Ordering::Relaxed);
        let requests_limited = self.metrics.requests_limited.load(Ordering::Relaxed);
        let active_limiters = self.metrics.active_limiters.load(Ordering::Relaxed);

        let mut report = MetricsReport::new("ratelimit-agent", 10_000);

        report.counters.push(CounterMetric::new(
            "ratelimit_requests_total",
            requests_total,
        ));
        report.counters.push(CounterMetric::new(
            "ratelimit_requests_allowed_total",
            requests_allowed,
        ));
        report.counters.push(CounterMetric::new(
            "ratelimit_requests_limited_total",
            requests_limited,
        ));
        report.gauges.push(GaugeMetric::new(
            "ratelimit_active_limiters",
            active_limiters as f64,
        ));

        Some(report)
    }

    /// Handle shutdown request
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Received shutdown request"
        );

        // Mark as draining to stop accepting new requests gracefully
        *self.draining.write() = true;
    }

    /// Handle drain request
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            duration_ms = duration_ms,
            reason = ?reason,
            "Received drain request"
        );

        // Mark as draining
        *self.draining.write() = true;
    }
}

impl RateLimitAgent {
    fn get_load_metrics(&self) -> LoadMetrics {
        let requests_total = self.metrics.requests_total.load(Ordering::Relaxed);
        let requests_limited = self.metrics.requests_limited.load(Ordering::Relaxed);

        LoadMetrics {
            in_flight: 0, // We process synchronously
            queue_depth: 0,
            avg_latency_ms: 0.0, // Rate limiting is sub-millisecond
            p50_latency_ms: 0.0,
            p95_latency_ms: 0.0,
            p99_latency_ms: 0.0,
            requests_processed: requests_total,
            requests_rejected: requests_limited,
            requests_timed_out: 0,
        }
    }
}

/// Extension trait for HealthStatus
trait HealthStatusExt {
    fn with_load(self, load: LoadMetrics) -> Self;
}

impl HealthStatusExt for HealthStatus {
    fn with_load(mut self, load: LoadMetrics) -> Self {
        self.load = Some(load);
        self
    }
}

/// Request processing logic
async fn process_request_headers(
    agent: &RateLimitAgent,
    event: RequestHeadersEvent,
) -> AgentResponse {
    agent.request_count.fetch_add(1, Ordering::Relaxed);
    agent.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    debug!(
        correlation_id = %event.metadata.correlation_id,
        method = %event.method,
        uri = %event.uri,
        client_ip = %event.metadata.client_ip,
        "Processing rate limit check"
    );

    // Find matching rule
    let rule = agent.find_matching_rule(&event);

    // Generate rate limit key
    let key = agent.generate_key(&rule.key, &event);

    debug!(
        rule = %rule.name,
        key = %key,
        rps = rule.requests_per_second,
        burst = rule.burst,
        "Applying rate limit rule"
    );

    // Get or create limiter
    let limiter = agent.get_or_create_limiter(key.clone(), &rule);

    // Check rate limit
    let limited = match limiter.check() {
        Ok(_) => {
            agent
                .metrics
                .requests_allowed
                .fetch_add(1, Ordering::Relaxed);
            false
        }
        Err(_) => {
            agent.limited_count.fetch_add(1, Ordering::Relaxed);
            agent
                .metrics
                .requests_limited
                .fetch_add(1, Ordering::Relaxed);
            true
        }
    };

    // Create response
    let mut response = if limited && !agent.config.read().dry_run {
        let status = rule.status_code.unwrap_or(429);
        let message = rule.message.clone().unwrap_or_else(|| {
            format!(
                "Rate limit exceeded: {} requests per second allowed",
                rule.requests_per_second
            )
        });

        warn!(
            correlation_id = %event.metadata.correlation_id,
            rule = %rule.name,
            key = %key,
            "Rate limit exceeded, blocking request"
        );

        let mut headers = HashMap::new();
        headers.insert(
            "X-RateLimit-Limit".to_string(),
            rule.requests_per_second.to_string(),
        );
        headers.insert("X-RateLimit-Remaining".to_string(), "0".to_string());
        headers.insert(
            "X-RateLimit-Reset".to_string(),
            (chrono::Utc::now() + chrono::Duration::seconds(1))
                .timestamp()
                .to_string(),
        );
        headers.insert("Retry-After".to_string(), "1".to_string());

        AgentResponse {
            version: zentinel_agent_protocol::v2::PROTOCOL_VERSION_2,
            decision: Decision::Block {
                status,
                body: Some(message),
                headers: Some(headers),
            },
            request_headers: vec![],
            response_headers: vec![],
            routing_metadata: HashMap::new(),
            audit: AuditMetadata::default(),
            needs_more: false,
            request_body_mutation: None,
            response_body_mutation: None,
            websocket_decision: None,
        }
    } else {
        if limited {
            info!(
                correlation_id = %event.metadata.correlation_id,
                rule = %rule.name,
                key = %key,
                "Rate limit exceeded (dry-run mode)"
            );
        }

        AgentResponse::default_allow()
    };

    // Add rate limit headers
    response = response
        .add_request_header(HeaderOp::Set {
            name: "X-RateLimit-Rule".to_string(),
            value: rule.name.clone(),
        })
        .add_request_header(HeaderOp::Set {
            name: "X-RateLimit-Key".to_string(),
            value: key.clone(),
        });

    // Add audit metadata
    let mut tags = vec!["ratelimit".to_string()];
    if limited {
        tags.push("limited".to_string());
    }

    let mut custom = HashMap::new();
    custom.insert("rule".to_string(), serde_json::Value::String(rule.name));
    custom.insert("key".to_string(), serde_json::Value::String(key));
    custom.insert("limited".to_string(), serde_json::Value::Bool(limited));
    custom.insert(
        "rps".to_string(),
        serde_json::Value::Number(rule.requests_per_second.into()),
    );

    let audit = AuditMetadata {
        tags,
        custom,
        ..Default::default()
    };

    response.with_audit(audit)
}

/// Default configuration
impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            rules: vec![],
            default: RateLimitRule {
                name: "default".to_string(),
                key: RateLimitKey::ClientIp,
                requests_per_second: 100,
                burst: 200,
                conditions: vec![],
                message: None,
                status_code: None,
            },
            dry_run: false,
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Initialize tracing
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        socket = ?args.socket,
        grpc_address = ?args.grpc_address,
        "Starting rate limit agent (v2 protocol)"
    );

    // Load configuration
    let config = if let Some(config_path) = args.config {
        info!("Loading configuration from {:?}", config_path);
        let config_str = tokio::fs::read_to_string(&config_path)
            .await
            .context("Failed to read configuration file")?;
        serde_yaml::from_str(&config_str).context("Failed to parse configuration")?
    } else {
        // Use default config with command-line overrides
        RateLimitConfig {
            default: RateLimitRule {
                name: "default".to_string(),
                key: RateLimitKey::ClientIp,
                requests_per_second: args.default_rps,
                burst: args.default_burst,
                conditions: vec![],
                message: None,
                status_code: None,
            },
            dry_run: args.dry_run,
            ..Default::default()
        }
    };

    info!(
        rules = config.rules.len(),
        default_rps = config.default.requests_per_second,
        dry_run = config.dry_run,
        "Rate limit configuration loaded"
    );

    // Create rate limit agent
    let agent = RateLimitAgent::new(config);

    // Create a clone for the cleanup task
    let cleanup_agent = agent.clone();
    let cleanup_interval = Duration::from_secs(args.cleanup_interval);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(cleanup_interval);
        loop {
            interval.tick().await;
            cleanup_agent
                .cleanup_expired_limiters(Duration::from_secs(300))
                .await;
        }
    });

    // Choose transport based on CLI arguments
    if let Some(grpc_addr) = args.grpc_address {
        // Use gRPC transport (v2)
        info!(address = %grpc_addr, "Starting gRPC server (v2 protocol)");

        let addr: std::net::SocketAddr =
            grpc_addr.parse().context("Invalid gRPC address format")?;

        let server = GrpcAgentServerV2::new("ratelimit-agent", Box::new(agent));

        info!("Rate limit agent ready and listening on gRPC");

        server
            .run(addr)
            .await
            .context("Failed to run rate limit agent gRPC server")?;
    } else {
        // Use UDS transport (v2)
        info!(socket = ?args.socket, "Starting UDS server (v2 protocol)");

        let server = UdsAgentServerV2::new("ratelimit-agent", args.socket, Box::new(agent));

        info!("Rate limit agent ready and listening on UDS");

        server
            .run()
            .await
            .context("Failed to run rate limit agent UDS server")?;
    }

    Ok(())
}
