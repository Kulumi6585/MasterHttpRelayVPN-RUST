use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file {0}: {1}")]
    Read(String, #[source] std::io::Error),
    #[error("failed to parse config json: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ScriptId {
    One(String),
    Many(Vec<String>),
}

impl ScriptId {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            ScriptId::One(s) => vec![s],
            ScriptId::Many(v) => v,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub mode: String,
    #[serde(default = "default_google_ip")]
    pub google_ip: String,
    #[serde(default = "default_front_domain")]
    pub front_domain: String,
    #[serde(default)]
    pub script_id: Option<ScriptId>,
    #[serde(default)]
    pub script_ids: Option<ScriptId>,
    pub auth_key: String,
    #[serde(default = "default_listen_host")]
    pub listen_host: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub socks5_port: Option<u16>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_verify_ssl")]
    pub verify_ssl: bool,
    #[serde(default)]
    pub hosts: HashMap<String, String>,
    #[serde(default)]
    pub enable_batching: bool,
}

fn default_google_ip() -> String {
    "216.239.38.120".into()
}
fn default_front_domain() -> String {
    "www.google.com".into()
}
fn default_listen_host() -> String {
    "127.0.0.1".into()
}
fn default_listen_port() -> u16 {
    8085
}
fn default_log_level() -> String {
    "warn".into()
}
fn default_verify_ssl() -> bool {
    true
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Read(path.display().to_string(), e))?;
        let cfg: Config = serde_json::from_str(&data)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.mode != "apps_script" {
            return Err(ConfigError::Invalid(format!(
                "only 'apps_script' mode is supported in this build (got '{}')",
                self.mode
            )));
        }
        if self.auth_key.trim().is_empty() || self.auth_key == "CHANGE_ME_TO_A_STRONG_SECRET" {
            return Err(ConfigError::Invalid(
                "auth_key must be set to a strong secret".into(),
            ));
        }
        let ids = self.script_ids_resolved();
        if ids.is_empty() {
            return Err(ConfigError::Invalid(
                "script_id (or script_ids) is required".into(),
            ));
        }
        for id in &ids {
            if id.is_empty() || id == "YOUR_APPS_SCRIPT_DEPLOYMENT_ID" {
                return Err(ConfigError::Invalid(
                    "script_id is not set — deploy Code.gs and paste its Deployment ID".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn script_ids_resolved(&self) -> Vec<String> {
        if let Some(s) = &self.script_ids {
            return s.clone().into_vec();
        }
        if let Some(s) = &self.script_id {
            return s.clone().into_vec();
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_script_id() {
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "MY_SECRET_KEY_123",
            "script_id": "ABCDEF"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert_eq!(cfg.script_ids_resolved(), vec!["ABCDEF".to_string()]);
        cfg.validate().unwrap();
    }

    #[test]
    fn parses_multi_script_id() {
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "MY_SECRET_KEY_123",
            "script_id": ["A", "B", "C"]
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert_eq!(cfg.script_ids_resolved(), vec!["A", "B", "C"]);
    }

    #[test]
    fn rejects_placeholder_script_id() {
        let s = r#"{
            "mode": "apps_script",
            "auth_key": "SECRET",
            "script_id": "YOUR_APPS_SCRIPT_DEPLOYMENT_ID"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_wrong_mode() {
        let s = r#"{
            "mode": "domain_fronting",
            "auth_key": "SECRET",
            "script_id": "X"
        }"#;
        let cfg: Config = serde_json::from_str(s).unwrap();
        assert!(cfg.validate().is_err());
    }
}
