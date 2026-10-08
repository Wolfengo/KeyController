use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    pub lifetime_seconds: u32,
}
impl Rules {
    pub fn validate(&self) -> Result<()> {
        if self.lifetime_seconds > 31_536_000 {
            Err(Error("invalid_lifetime"))
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeySettings {
    pub fingerprint_mode: bool,
    pub rules: Option<Rules>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub scanned: bool,
    pub global: Rules,
    // Existing installations retain timer-only behavior until explicitly
    // enabling system-sleep revocation. Per-key rules stay lifetime-only.
    #[serde(default)]
    pub revoke_on_sleep: bool,
    pub keys: BTreeMap<String, KeySettings>,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct GlobalRules {
    pub lifetime_seconds: u32,
    pub revoke_on_sleep: bool,
}
impl Settings {
    pub fn global_rules(&self) -> GlobalRules {
        GlobalRules {
            lifetime_seconds: self.global.lifetime_seconds,
            revoke_on_sleep: self.revoke_on_sleep,
        }
    }
    // Only persisted settings may contain the obsolete boolean. Keep the API
    // strict, and never turn malformed or unknown stored values into defaults.
    pub fn from_persisted(mut value: serde_json::Value) -> Result<(Self, bool)> {
        fn migrate(rules: &mut serde_json::Value) -> Result<bool> {
            let Some(object) = rules.as_object_mut() else {
                return Ok(false);
            };
            match object.get("revoke_on_lock") {
                None => Ok(false),
                Some(serde_json::Value::Bool(_)) => {
                    object.remove("revoke_on_lock");
                    Ok(true)
                }
                Some(_) => Err(Error("invalid_settings")),
            }
        }
        let mut migrated = false;
        if let Some(global) = value.get_mut("global") {
            migrated |= migrate(global)?;
        }
        if let Some(keys) = value
            .get_mut("keys")
            .and_then(serde_json::Value::as_object_mut)
        {
            for key in keys.values_mut() {
                if let Some(rules) = key.get_mut("rules") {
                    migrated |= migrate(rules)?;
                }
            }
        }
        let settings: Self = serde_json::from_value(value)?;
        settings.global.validate()?;
        for key in settings.keys.values() {
            if let Some(rules) = &key.rules {
                rules.validate()?;
            }
        }
        Ok((settings, migrated))
    }

    pub fn effective(&self, id: &str) -> Rules {
        self.keys
            .get(id)
            .and_then(|k| k.rules.clone())
            .unwrap_or_else(|| self.global.clone())
    }
}
#[derive(Default)]
pub struct RequestGate {
    windows: VecDeque<u64>,
    dialog_windows: VecDeque<u64>,
    cooldown: BTreeMap<String, u64>,
    pub active: Option<(String, String)>,
}
impl RequestGate {
    // Metadata scans share the operation slot but do not create consent windows.
    pub fn check_active(&self, key: &str) -> Result<Option<String>> {
        if let Some((active_key, request)) = &self.active {
            return if active_key == key {
                Ok(Some(request.clone()))
            } else {
                Err(Error("busy"))
            };
        }
        Ok(None)
    }
    // Unlock consent windows share this quota, regardless of caller executable.
    // Coalescing precedes throttling and never resets the active deadline.
    pub fn check(&mut self, key: &str, now: u64) -> Result<Option<String>> {
        if let Some(active) = self.check_active(key)? {
            return Ok(Some(active));
        }
        if self.cooldown.get(key).is_some_and(|until| now < *until) {
            return Err(Error("cooldown"));
        }
        self.windows.retain(|t| now.saturating_sub(*t) < 60);
        if self.windows.len() >= 3 {
            return Err(Error("rate_limited"));
        }
        self.windows.push_back(now);
        Ok(None)
    }
    // Opening desktop dialogs has its own flood limit. Closing a management
    // dialog is not an unlock refusal and must never delay access requests.
    pub fn check_dialog(&mut self, key: &str, now: u64) -> Result<Option<String>> {
        if let Some(active) = self.check_active(key)? {
            return Ok(Some(active));
        }
        self.dialog_windows.retain(|t| now.saturating_sub(*t) < 60);
        if self.dialog_windows.len() >= 3 {
            return Err(Error("rate_limited"));
        }
        self.dialog_windows.push_back(now);
        Ok(None)
    }
    pub fn finish(&mut self, key: &str, cancelled: bool, now: u64) {
        self.active = None;
        if cancelled {
            self.cooldown.insert(key.into(), now + 30);
        }
        self.cooldown.retain(|_, t| *t > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn legacy_rules_migrate_without_losing_durations_modes_or_scan_state() {
        let value = json!({
            "scanned": true,
            "global": {"lifetime_seconds": 900, "revoke_on_lock": true},
            "keys": {
                "a": {"fingerprint_mode": true, "rules": null},
                "b": {"fingerprint_mode": false, "rules": {
                    "lifetime_seconds": 45, "revoke_on_lock": false
                }}
            }
        });
        let (settings, migrated) = Settings::from_persisted(value).unwrap();
        assert!(migrated);
        assert!(settings.scanned);
        assert_eq!(settings.effective("a").lifetime_seconds, 900);
        assert_eq!(settings.effective("b").lifetime_seconds, 45);
        assert!(settings.keys["a"].fingerprint_mode);
        assert!(!settings.keys["b"].fingerprint_mode);
        assert!(settings.keys["a"].rules.is_none());
        let saved = serde_json::to_value(settings).unwrap();
        assert!(!saved.to_string().contains("revoke_on_lock"));
        assert!(!Settings::from_persisted(saved).unwrap().1);
    }

    #[test]
    fn migration_rejects_malformed_or_unknown_settings() {
        let original = json!({
            "scanned": false,
            "global": {"lifetime_seconds": 0, "revoke_on_lock": true},
            "keys": {"a": {"fingerprint_mode": true, "rules": {
                "lifetime_seconds": 30, "revoke_on_lock": false
            }}}
        });
        for invalid in [json!(null), json!(1), json!("false"), json!([])] {
            for pointer in ["/global/revoke_on_lock", "/keys/a/rules/revoke_on_lock"] {
                let mut value = original.clone();
                *value.pointer_mut(pointer).unwrap() = invalid.clone();
                assert!(Settings::from_persisted(value).is_err());
            }
        }
        for pointer in ["/global/lifetime_seconds", "/keys/a/rules/lifetime_seconds"] {
            for invalid in [json!(-1), json!(31_536_001), json!("30"), json!(null)] {
                let mut value = original.clone();
                *value.pointer_mut(pointer).unwrap() = invalid;
                assert!(Settings::from_persisted(value).is_err());
            }
        }
        let mut unknown = original.clone();
        unknown["global"]["unknown_policy"] = json!(true);
        assert!(Settings::from_persisted(unknown).is_err());
        let mut missing = original;
        missing.as_object_mut().unwrap().remove("scanned");
        assert!(Settings::from_persisted(missing).is_err());
        assert!(Settings::from_persisted(json!({})).is_err());
        // Migration is a stored-file compatibility path, never an API policy.
        assert!(
            serde_json::from_value::<Rules>(json!({
                "lifetime_seconds": 30, "revoke_on_lock": true
            }))
            .is_err()
        );
    }

    #[test]
    fn request_coalescing_busy_and_cooldown() {
        let mut g = RequestGate::default();
        assert_eq!(g.check("a", 0).unwrap(), None);
        g.active = Some(("a".into(), "r".into()));
        assert_eq!(g.check("a", 1).unwrap(), Some("r".into()));
        assert_eq!(g.check("b", 1).unwrap_err().0, "busy");
        g.finish("a", true, 2);
        assert_eq!(g.check("a", 31).unwrap_err().0, "cooldown");
        assert_eq!(g.check("a", 3).unwrap_err().0, "cooldown");
        assert!(g.check("a", 32).is_ok());
    }
    #[test]
    fn unlock_windows_share_rate_limit_and_scan_only_uses_active_slot() {
        let mut g = RequestGate::default();
        for t in 0..3 {
            assert!(g.check("a", t).is_ok());
        }
        assert_eq!(g.check("b", 59).unwrap_err().0, "rate_limited");
        assert!(g.check_active("__scan").is_ok());
        g.active = Some(("b".into(), "active-window".into()));
        assert_eq!(g.check_active("__scan").unwrap_err().0, "busy");
        assert_eq!(g.check("b", 59).unwrap(), Some("active-window".into()));
        g.active = None;
        assert!(g.check("b", 60).is_ok());
    }
    #[test]
    fn desktop_dialog_quota_is_separate_and_has_no_cancel_cooldown() {
        let mut g = RequestGate::default();
        for now in 0..3 {
            assert_eq!(g.check_dialog("a", now).unwrap(), None);
            g.active = Some(("a".into(), "dialog".into()));
            assert_eq!(g.check("other", now).unwrap_err().0, "busy");
            g.finish("a", false, now);
        }
        assert_eq!(g.check_dialog("b", 59).unwrap_err().0, "rate_limited");
        // Cancelling management consumed no unlock windows and no cooldown.
        for now in 3..6 {
            assert_eq!(g.check("a", now).unwrap(), None);
        }
        assert_eq!(g.check("b", 59).unwrap_err().0, "rate_limited");
        assert!(g.check_dialog("a", 60).is_ok());
        assert!(g.check("a", 63).is_ok());
    }

    #[test]
    fn unlock_cooldown_does_not_block_desktop_dialogs() {
        let mut g = RequestGate::default();
        g.check("a", 0).unwrap();
        g.finish("a", true, 1);
        assert_eq!(g.check("a", 2).unwrap_err().0, "cooldown");
        assert_eq!(g.check_dialog("a", 2).unwrap(), None);
        g.finish("a", false, 3);
        assert_eq!(g.check("a", 4).unwrap_err().0, "cooldown");
    }
    #[test]
    fn sleep_policy_defaults_off_and_never_enters_individual_rules() {
        let legacy = json!({"scanned":true,"global":{"lifetime_seconds":900},"keys":{
            "a":{"fingerprint_mode":true,"rules":{"lifetime_seconds":45}}
        }});
        let (settings, migrated) = Settings::from_persisted(legacy.clone()).unwrap();
        assert!(!migrated && !settings.revoke_on_sleep);
        assert!(!Settings::default().revoke_on_sleep);
        for enabled in [true, false] {
            let mut saved = legacy.clone();
            saved["revoke_on_sleep"] = json!(enabled);
            let (settings, _) = Settings::from_persisted(saved).unwrap();
            assert_eq!(settings.revoke_on_sleep, enabled);
            assert_eq!(
                settings.global_rules(),
                GlobalRules {
                    lifetime_seconds: 900,
                    revoke_on_sleep: enabled
                }
            );
            assert_eq!(
                settings.effective("a"),
                Rules {
                    lifetime_seconds: 45
                }
            );
            assert!(settings.keys["a"].fingerprint_mode);
        }
        for invalid in [json!(null), json!(1), json!("true")] {
            let mut saved = legacy.clone();
            saved["revoke_on_sleep"] = invalid;
            assert!(Settings::from_persisted(saved).is_err());
        }
        assert!(
            serde_json::from_value::<Rules>(json!({"lifetime_seconds":900,"revoke_on_sleep":true}))
                .is_err()
        );
    }

    #[test]
    fn inheritance_and_mode_are_independent() {
        let mut s = Settings::default();
        s.keys.insert(
            "a".into(),
            KeySettings {
                fingerprint_mode: true,
                rules: None,
            },
        );
        s.global.lifetime_seconds = 90;
        assert_eq!(s.effective("a").lifetime_seconds, 90);
        s.keys.get_mut("a").unwrap().rules = Some(Rules {
            lifetime_seconds: 12,
        });
        s.keys.get_mut("a").unwrap().fingerprint_mode = false;
        assert_eq!(s.effective("a").lifetime_seconds, 12);
        assert!(!s.keys["a"].fingerprint_mode);
    }
}
