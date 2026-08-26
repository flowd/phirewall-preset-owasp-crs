# Changelog

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- **CRS-style anomaly scoring.** Every matching rule contributes its `severity` score (CRITICAL 5, ERROR 4, WARNING 3, NOTICE 2; missing/unknown severity scores as CRITICAL), and the request is blocked once the accumulated score reaches the anomaly threshold (`>=`, default 5, the CRS standard). `CoreRuleSet::evaluate()` returns a `RuleSetEvaluation` (total score, threshold, matched rules with severity/paranoia level/expanded logdata, fail-closed and early-stop flags); `CoreRuleSetMatcher` and both presets accept an `anomalyThreshold`. Evaluation stops once the threshold is reached; `evaluate(..., stopWhenThresholdReached: false)` evaluates every rule for complete diagnostics. Fail-closed decisions (capped variable, PCRE subject error) block regardless of the threshold.
- **Target exclusions for false-positive tuning.** `excludeTarget('ARGS:/^utm_/')`, `excludeTargetById(942431, 'ARGS:fbclid')` and `excludeTargetByTag('attack-sqli', 'ARGS:comment')` on `CoreRuleSet` and `CoreRuleSetMatcher` remove a parameter (exact name, name pattern or whole variable) from inspection - globally, per rule id (CRS `SecRuleUpdateTargetById` style) or per rule tag. Exclusions are runtime tuning, never part of the compiled-data cache, and cannot lift the collection cap.
- **Value manipulators (advanced).** `addManipulator()` / `addManipulatorById()` register a `RequestValueManipulatorInterface` (or closure) transforming collected values before rules match; returning an empty string removes the value from inspection. Manipulators run after exclusions; global manipulator results are computed once per variable per request. Documented with an explicit warning: manipulators weaken detection, and their exceptions propagate.
- **PSR-3 match logging with expanded `logdata`.** Both presets and `CoreRuleSetMatcher` accept a `logger`. Every rule match logs at `info` level - including sub-threshold matches on requests that pass, the tuning signal for finding false positives - with rule id, severity, score, paranoia level, matched variable and the rule's CRS `logdata:` template expanded (`%{TX.0}`, `%{MATCHED_VAR_NAME}`, `%{MATCHED_VAR}`), sanitized and length-bounded. Blocked requests additionally log a `warning` with total score, threshold and all matched rule ids. New dependency: `psr/log`.
- **Presets accept a `configure` closure** receiving the `CoreRuleSetMatcher` for tuning (exclusions, manipulators, enable/disable) before the first request; calls made before the rules load are queued, invalid selectors fail eagerly.
- `manifest.json` records kept rule counts per severity (`ruleCountsBySeverity`); older manifests without the field stay readable.

### Changed

- **BREAKING: `CoreRuleSet::match(): ?int` was replaced by `evaluate(): RuleSetEvaluation`.** First-match blocking is approximated with `anomalyThreshold: 1`.
- **BREAKING (behavioral): presets block at accumulated anomaly score >= 5 instead of on the first match.** Practical impact on the bundled snapshot is small: 177 of 185 shipped rules are CRITICAL (5) and still block alone; only the 8 WARNING rules (920230, 920260, 942420, 942421, 942430, 942431, 942432, 942460) no longer block solo - two of them together do. The fail2ban preset counts a request toward the ban only when the request itself reached the anomaly threshold; scores never accumulate across requests.
- **BREAKING: `VariableCollectorInterface::collect()` returns named entries** (`list<array{name: ?string, value: string}>`) instead of a flat value list, so selectors and exclusions can address parameters by name. `RequestVariableValues::entriesFor()` exposes the named form; `valuesFor()` remains.
- **Named and negated rule-text selectors are honored.** `REQUEST_HEADERS:User-Agent` now collects (only) that header - rules targeting solely named headers are no longer dropped at import - and CRS exclusions such as `!REQUEST_HEADERS:Cookie` (16 shipped rules) and `!ARGS_NAMES:/.../` now take effect, removing a known source of cookie-driven false positives. Rerun `bin/crs-import` to pick up the previously dropped header rules.
- **BREAKING (behavioral): a single collected value longer than `CoreRule::MAX_INSPECTABLE_VALUE_LENGTH` (2048 bytes) now fails closed (blocks) for every operator.** Previously `@rx` truncated an oversized value to an 8192-byte head and inspected only that (so a payload padded past the head slipped through), while the phrase/substring operators scanned the whole value unbounded. Both are replaced by one contract - an oversized single value is un-inspectable, so the rule fails closed - mirroring the existing per-variable count cap. This closes a padding-based `@rx` evasion, bounds worst-case regex backtracking (no oversized subject reaches the engine), and removes an unbounded-CPU vector on large values. Behavior change to note: a request carrying one field larger than 2048 bytes that does not otherwise match is now blocked rather than passed - relevant for legitimately large single values (e.g. long tokens in a cookie/`Authorization` header, base64 fields). The limit is configurable per rule set via `CoreRuleSet::setMaxInspectableValueLength()` and `CoreRuleSetMatcher::setMaxInspectableValueLength()` (reachable through the presets' `configure:` closure): raise it for deployments with legitimately large single values, lower it to tighten the regex-cost bound. `RegexEvaluator` no longer truncates.
- `MatchResult` metadata now carries `owasp_anomaly_score`, `owasp_anomaly_threshold`, `owasp_rule_ids`, `owasp_log_data` and `owasp_fail_closed` alongside `owasp_rule_id`/`msg`; blocked responses gain the `X-Phirewall-Owasp-Score` diagnostic header, and `X-Phirewall-Owasp-Rule` may list multiple ids (capped at 10, then `,+N`).
- The compiled-data cache schema version was bumped (v2); existing artifacts rebuild automatically.

## 0.4.1 - 2026-08-20

### Changed

- **Updated the bundled OWASP Core Rule Set from v4.27.0 to v4.29.0.** Automated import via the scheduled `CRS Update` workflow; the rules are filtered and split per paranoia level as before. Upstream changes are listed in the [CRS release notes](https://github.com/coreruleset/coreruleset/releases).

### Fixed

- **Nested cookie params no longer break `REQUEST_COOKIES` collection.** PHP parses a bracketed cookie name (`Cookie: foo[a]=1`) into a nested array, exactly like query parameters. Casting that array raised an "Array to string conversion" warning (fatal under strict production error handlers) and scanned the literal string `Array` instead of the cookie payload. The collector now flattens cookie params to their scalar leaf values, so nested cookie payloads are scanned by the rules.

## 0.4.0 - 2026-07-27

### Added

- **Lazy rule loading with compiled-data caching.** `CoreRuleSetMatcher::fromRuleFiles($paranoiaLevel, $rulesDirectory, $maxValuesPerCrsVariable)` defers parsing to the first evaluated request, and when the evaluating `Config` carries a compiled-data cache (`Config::setCompiledDataCache()`), the parsed rules load from an OPcache-served compiled artifact instead of being re-parsed on every request. `enable()`/`disable()` calls made before the first use are queued and applied once the rules are loaded. `Presets::blocklist()` and `Presets::fail2ban()` now build lazily; a matcher constructed with an already parsed `CoreRuleSet` behaves as before and ignores the cache. `CoreRule` gained `toArray()`/`fromArray()` for the artifact round-trip, and the artifact identifier carries a format version so an upgrade that changes that shape rebuilds automatically.

## 0.3.0 - 2026-07-27

### Added

- **`CoreRuleSetMatcher` emits `diagnostic_headers` metadata.** A matched rule now carries `diagnostic_headers` (`['X-Phirewall-Owasp-Rule' => <id>]`) alongside the existing `owasp_rule_id` and `msg` metadata. phirewall 0.9 copies these onto the blocked response when `Config::enableDiagnosticsHeaders()` is active - the generic replacement for the hardcoded OWASP header that 0.9 removed - and it works wherever the matcher decides the block (blocklist rule or fail2ban filter). `owasp_rule_id` (int) and `msg` remain available as structured metadata for event listeners.

### Changed

- Require `flowd/phirewall` `>=0.9 <1.0` (was `>=0.8 <1.0`). phirewall 0.9 removed the hardcoded OWASP diagnostics header, so the generic `diagnostic_headers` mechanism above needs it. (The fail2ban block-on-match semantics below are a phirewall 0.8 behaviour that carries into 0.9 unchanged.)
- **BREAKING (behavioural): the fail2ban preset now blocks every CRS match, not only the one that reaches the threshold.** This follows the fail2ban semantics change in phirewall 0.8: a CRS match marks a request as malicious, so `Presets::fail2ban()` now blocks every match with a 403. A match below the threshold blocks and counts (dispatching `Fail2BanMatched`); the threshold-th match within the period additionally bans the client key (dispatching `Fail2BanBanned`), so all further traffic from that key is blocked until the ban expires. Under 0.7 a match below the threshold passed through and only counted, so the preset acted as a slow counter. There is no migration for CRS traffic: a CRS filter only matches unambiguously malicious requests, so blocking them immediately is intended. The blocklist preset (`Presets::blocklist()`) is unchanged.
