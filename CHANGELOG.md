# Changelog

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- **`CoreRuleSetMatcher` emits `diagnostic_headers` metadata.** A matched rule now carries `diagnostic_headers` (`['X-Phirewall-Owasp-Rule' => <id>]`) alongside the existing `owasp_rule_id` and `msg` metadata. phirewall 0.9 copies these onto the blocked response when `Config::enableDiagnosticsHeaders()` is active - the generic replacement for the hardcoded OWASP header that 0.9 removed - and it works wherever the matcher decides the block (blocklist rule or fail2ban filter). `owasp_rule_id` (int) and `msg` remain available as structured metadata for event listeners.

### Changed

- Require `flowd/phirewall` `^0.9.0` (was `^0.6`); the diagnostic-header mechanism and the fail2ban semantics below need 0.9.
- **BREAKING (behavioural): the fail2ban preset now blocks every CRS match, not only the one that reaches the threshold.** This follows the fail2ban semantics change in phirewall 0.8: a CRS match marks a request as malicious, so `Presets::fail2ban()` now blocks every match with a 403. A match below the threshold blocks and counts (dispatching `Fail2BanMatched`); the threshold-th match within the period additionally bans the client key (dispatching `Fail2BanBanned`), so all further traffic from that key is blocked until the ban expires. Under 0.7 a match below the threshold passed through and only counted, so the preset acted as a slow counter. There is no migration for CRS traffic: a CRS filter only matches unambiguously malicious requests, so blocking them immediately is intended. The blocklist preset (`Presets::blocklist()`) is unchanged.
