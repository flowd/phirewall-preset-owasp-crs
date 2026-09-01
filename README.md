# Phirewall OWASP Core Rule Set

OWASP [Core Rule Set (CRS)](https://github.com/coreruleset/coreruleset) support for
[flowd/phirewall](https://github.com/flowd/phirewall), the PSR-7/PSR-15 PHP firewall.

This package provides two things:

1. **The ModSecurity SecRule engine** (`Flowd\PhirewallPresetOwaspCrs\Engine\`) - a parser and
   evaluator for ModSecurity-style `SecRule` directives, usable with any
   ruleset. It was extracted from the core `flowd/phirewall` package in 0.6.
2. **Ready-made CRS presets** - a pre-filtered, per-paranoia-level snapshot of
   the CRS request rules, exposed as `Config` overlays. Evaluation uses CRS-style
   [anomaly scoring](#anomaly-scoring): every matching rule contributes its severity
   score, and the request is blocked once the accumulated score reaches the threshold.
   - **Blocklist preset** - block every request whose anomaly score reaches the threshold.
   - **Fail2Ban preset** - block scoring requests and additionally ban a client key that keeps scoring.

## Installation

```bash
composer require flowd/phirewall-preset-owasp-crs
```

## Usage

Presets are `ConfigLayer`s. Apply them onto your existing configuration with
`Config::with()` (the preset never brings its own cache; your Config's cache,
event dispatcher and clock stay in charge):

```php
use Flowd\Phirewall\Config;
use Flowd\PhirewallPresetOwaspCrs\ParanoiaLevel;
use Flowd\PhirewallPresetOwaspCrs\Presets;

$config = $config->with(
    Presets::blocklist(ParanoiaLevel::Level1),
);
```

Want to also ban probing clients, not just block their scoring requests? Use the fail2ban
preset. It blocks every request whose anomaly score reaches the threshold, like the blocklist,
and additionally bans the client key (the IP by default) once it produced `threshold`
such requests within `period` seconds, so all further traffic from that key is blocked
until the ban expires:

```php
$config = $config->with(
    Presets::fail2ban(ParanoiaLevel::Level1, threshold: 5, period: 600, ban: 3600),
);
```

Both presets accept an `anomalyThreshold` (default 5, the CRS standard), a `configure`
closure for [tuning](#excluding-parameters-from-rules-false-positives) and a PSR-3
`logger` for [match logging](#logging):

```php
$config = $config->with(Presets::blocklist(
    ParanoiaLevel::Level1,
    anomalyThreshold: 5,
    configure: static function (CoreRuleSetMatcher $matcher): void {
        $matcher->excludeTarget('ARGS:/^utm_/');
    },
    logger: $logger,
));
```

For manual wiring (custom rule name, enabling/disabling single CRS rule ids), get the
raw rule set:

```php
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;

$coreRuleSet = Presets::coreRuleSet(ParanoiaLevel::Level2);
$coreRuleSet->disable(942430);
$config->blocklists->addRule(new BlocklistRule('my-crs-rule', new CoreRuleSetMatcher($coreRuleSet)));
```

`Presets::crsVersion()` returns the bundled upstream release tag.

### Anomaly scoring

Like upstream CRS, every matching rule contributes its severity score to the request's
anomaly score, and the request is blocked once the accumulated score **reaches** the
threshold (`score >= threshold`):

| Severity | Score |
| --- | --- |
| CRITICAL | 5 |
| ERROR | 4 |
| WARNING | 3 |
| NOTICE | 2 |

The default threshold is 5, the CRS standard inbound threshold. In the bundled CRS
snapshot most rules are CRITICAL and still block on their own; WARNING rules (for
example the `942430` restricted-character checks, a classic source of false positives)
no longer block alone - two of them together do. `anomalyThreshold: 1` restores
block-on-first-match behaviour; raising the threshold above 5 substantially increases
the risk of attacks passing.

Details:

- A rule without a recognizable `severity` action scores 5 (CRITICAL) - a bare
  `deny` rule in a custom ruleset still blocks alone at the default threshold.
- Evaluation stops once the threshold is reached. `CoreRuleSet::evaluate()` accepts
  `stopWhenThresholdReached: false` to evaluate every rule for complete diagnostics.
- Fail-closed decisions bypass the threshold: a variable truncated at the collection
  cap, a single value longer than the per-value inspection limit (2048 bytes,
  configurable via `CoreRuleSet::setMaxInspectableValueLength()`), or a PCRE subject
  error on a value blocks immediately, whatever the score.
- An *unexpected* engine fault (e.g. a manipulator that throws) follows the firewall's
  fail-open policy: the request is allowed under the default fail-open (with a
  `FirewallError` event) and blocked when fail-open is disabled - the matcher is
  `FailOpenAware`.
- Scores never accumulate across requests. The fail2ban preset counts a request
  toward the ban whenever CRS blocks it - when its score reaches the threshold or
  the request fails closed.

A request blocked on its anomaly score - or by a rule-level fail-closed outcome (a
capped variable, an oversized value, or a PCRE subject error) - carries
`owasp_anomaly_score`, `owasp_anomaly_threshold`, `owasp_rule_ids` (comma-separated)
and `owasp_rule_id` (first match); it also carries `msg`, `owasp_matched_variable`
(the matched target, e.g. `REQUEST_HEADERS:User-Agent` - the member name keeps the
casing the client sent), `owasp_matched_value` (the value the rule fired on, readable
so the match can be understood; sanitized, length-bounded and `[redacted]` for
credential targets such as cookie values and `Authorization`-type headers) and
`owasp_log_data` when the first matching rule provides them, and `owasp_fail_closed`
on a fail-closed block (there `owasp_matched_variable` names the variable that
failed closed).
With `Config::enableDiagnosticsHeaders()` such blocked responses carry
`X-Phirewall-Owasp-Rule` (up to 10 rule ids, then `,+N`) and
`X-Phirewall-Owasp-Score` (`score/threshold`). A block from an engine-internal fault
under a fail-closed policy (`useFailOpen(false)`) instead carries only
`owasp_anomaly_threshold` and `owasp_fail_closed` - no scoring metadata or diagnostics
headers, since no rule scored.

### Excluding parameters from rules (false positives)

Marketing and tracking parameters (`utm_*`, `fbclid`, ...) regularly carry values
that look like attack payloads to CRS rules. Instead of disabling whole rules,
exclude the parameter from inspection - globally, per rule id (CRS
`SecRuleUpdateTargetById` style) or per rule tag:

```php
$coreRuleSet = Presets::coreRuleSet(ParanoiaLevel::Level1)
    ->excludeTarget('ARGS:/^utm_/')            // all rules ignore utm_* values
    ->excludeTarget('ARGS_NAMES:/^utm_/')      // ... and the utm_* parameter names
    ->excludeTargetById(942431, 'ARGS:fbclid') // one rule ignores one parameter
    ->excludeTargetByTag('attack-sqli', 'ARGS:comment');
```

Selector forms: bare variable (`ARGS`), exact name (`ARGS:utm_source`) or name
pattern (`ARGS:/^utm_/`). Header names match case-insensitively, argument and
cookie names case-sensitively. Excluding a parameter's value usually wants its
name excluded too (the `ARGS_NAMES` twin), since rules also inspect parameter names.

The same methods exist on `CoreRuleSetMatcher` (queued until the rules load) and are
reachable through the presets' `configure:` closure. Exclusions are runtime tuning:
they never enter the compiled-data cache artifact, and they cannot lift the
collection cap - a request padded past the cap still fails closed.

**Limitation:** exclusions do not rewrite the raw `QUERY_STRING`/`REQUEST_URI`
values, so the few rules inspecting those (`920260`, `920540`, `920460` inspect
`REQUEST_URI`; `931110` inspects `QUERY_STRING`) still see the full string. If one
of them false-positives, use `disable($ruleId)`, a manipulator, or a bare-variable
exclusion naming the variable that rule actually inspects -
`excludeTargetById(920260, 'REQUEST_URI')` or `excludeTargetById(931110,
'QUERY_STRING')`. A selector naming a variable the rule does not target is accepted
but silently does nothing.

### Manipulators (advanced, weakens detection)

A manipulator transforms collected values before rules match against them - the
escape hatch for cases where excluding a whole parameter is too broad. Returning
an empty string removes the value from inspection:

```php
use Flowd\PhirewallPresetOwaspCrs\Engine\Variable\RequestValueManipulatorInterface;

$coreRuleSet->addManipulator(
    static fn (string $variable, ?string $name, string $value): string
        => $name === 'fbclid' ? '' : $value,
);
$coreRuleSet->addManipulatorById(942431, $manipulator); // scoped to one rule
```

> **Warning:** whatever a manipulator removes or rewrites is invisible to every
> rule it applies to - including real attack payloads hidden inside the removed
> content. Prefer target exclusions; keep manipulators as narrow as possible.
> Exceptions thrown by a manipulator propagate to the caller.

Manipulators run after exclusions. Global manipulators are applied once per
variable per request and shared across all rules; per-rule manipulators
specialize from that shared result.

### Logging

Pass a PSR-3 logger to either preset (or to `CoreRuleSetMatcher`) to log every
rule match at `info` level - **including matches on requests that stay below the
threshold and pass**. Those sub-threshold entries are the tuning signal: watch
them to find false-positive patterns (a `utm_content` value hitting `942431`,
say) before scores ever accumulate to a block, then add a target exclusion.
Blocked requests additionally log a `warning` with the total score, threshold
and all matched rule ids.

The per-match log context carries `rule_id`, `severity`, `anomaly_score`,
`paranoia_level`, `matched_variable` (e.g. `ARGS:utm_content`), `matched_value`
(the value the rule fired on; `[redacted]` for credential targets), `msg`,
`fail_closed`, `method`, `path` and `log_data` - the rule's CRS `logdata:`
template expanded with the matched data (`%{TX.0}`, `%{MATCHED_VAR_NAME}`,
`%{MATCHED_VAR}`); the warning context carries `total_score`,
`anomaly_threshold`, `rule_ids`, `fail_closed`, `method` and `path`.
Attacker-controlled context values (`matched_variable`, `matched_value`, `path`,
`log_data`) are sanitized (control characters stripped) and length-bounded before
they reach the log line. When the matched target is a credential - a cookie or an
`Authorization`, `Cookie`, `Proxy-Authorization`, `X-Api-Key` or `X-Auth-Token`
header - its value (and captures) is replaced with `[redacted]` in `matched_value`,
`log_data` and the `owasp_log_data`/`owasp_matched_value` metadata; the target name
is kept for tuning.

### Using the SecRule engine directly

The engine can load any ModSecurity-style ruleset, not just the bundled CRS:

```php
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;
use Flowd\PhirewallPresetOwaspCrs\Engine\SecRuleLoader;

$coreRuleSet = SecRuleLoader::fromString(
    'SecRule ARGS "@rx (?i)\bunion\b.*\bselect\b" "id:942100,phase:2,deny,msg:\'SQLi\'"',
);
// or: SecRuleLoader::fromDirectory('/path/to/rules')

$config->blocklists->addRule(new BlocklistRule('owasp', new CoreRuleSetMatcher($coreRuleSet)));
```

The engine implements a pragmatic subset of ModSecurity; see the table below.

### Paranoia levels

Like upstream CRS, paranoia levels are cumulative: `ParanoiaLevel::Level2` activates
all level 1 and level 2 rules. Level 1 is designed to be safe for most applications;
higher levels detect more but produce more false positives. In this snapshot almost
every rule at every level is CRITICAL and blocks on its own at the default threshold;
only the handful of WARNING rules merely accumulate score. Raising the paranoia level
therefore mostly adds more CRITICAL rules, so expect more blocking (and more false
positives), not just more accumulated score. Start with level 1, watch the
[match log](#logging) with a higher level against your real traffic, add
[exclusions](#excluding-parameters-from-rules-false-positives) for the false
positives you find, then raise the level.

### Skipping the per-request parse

Parsing the CRS rule files costs several milliseconds and, under PHP-FPM, would
run on every request. Both presets therefore load lazily: the parse happens on
the first evaluated request. To also skip that first parse per process, give
your `Config` a compiled-data cache (phirewall 0.9 or newer) - the parsed rules are
then served from an OPcache-backed artifact and re-parsed only when a rule file
changes:

```php
use Flowd\Phirewall\Support\CompiledDataCache;

$config->setCompiledDataCache(new CompiledDataCache('/path/to/var/cache/phirewall'));
$config = $config->with(Presets::blocklist(ParanoiaLevel::Level1));
```

For manual wiring use the lazy factory; rule toggles before the first request
are queued and applied once the rules are loaded:

```php
$matcher = CoreRuleSetMatcher::fromRuleFiles(ParanoiaLevel::Level1);
$matcher->disable(941110);

$config->blocklists->addRule(new BlocklistRule('owasp', $matcher));
```

A matcher constructed with an already parsed `CoreRuleSet` keeps the eager
behaviour and ignores the cache.

## What is included (and what is not)

Phirewall's SecRule engine implements a pragmatic subset of ModSecurity. The import
process therefore ships only the CRS rules that the engine can evaluate faithfully:

| Filter | Effect |
| --- | --- |
| Request phase only | `RESPONSE-*.conf` files and exclusion templates are skipped |
| Blocking rules only | Rules without a `deny`/`block` action (initialization, control flow) are dropped; kept rules contribute their `severity` score to the anomaly total |
| No chains | Chained rules are dropped entirely; keeping only a chain's first condition would over-block |
| Supported operators | `@rx`, `@contains`, `@streq`, `@beginsWith`, `@endsWith`, `@pm`, `@pmFromFile`; everything else (`@detectSQLi`, `@validateByteRange`, ...) is dropped |
| Supported targets | `REQUEST_URI`, `REQUEST_METHOD`, `QUERY_STRING`, `ARGS`, `ARGS_NAMES`, `REQUEST_COOKIES`, `REQUEST_COOKIES_NAMES`, `REQUEST_HEADERS`, `REQUEST_HEADERS_NAMES`, `REQUEST_FILENAME` - bare or with a named selector (`REQUEST_HEADERS:User-Agent`, `!ARGS_NAMES:/^utm_/`); rules whose positive targets are all unsupported (`XML:/*`, `REQUEST_BODY`, ...) are dropped |

Further engine differences to be aware of:

- **Bodies are inspected only as parsed arguments.** Query and form parameters are
  examined as `ARGS`; the engine does not parse raw JSON/XML bodies or inspect
  uploaded files (no `REQUEST_BODY`/`XML`/`FILES` collection), so a payload that
  appears only there is not seen.
- **No transformations.** `t:lowercase`, `t:urlDecodeUni` and friends are ignored;
  rules are evaluated against the raw collected values. As one deliberate exception,
  the string operators (`@streq`, `@contains`, `@beginsWith`, `@endsWith`) fold case,
  reproducing the common CRS pattern of a `t:lowercase` transformation plus a
  lowercase literal; a rule that genuinely wanted case-sensitive matching without
  `t:lowercase` is matched case-insensitively instead (a safe over-match, never an
  under-match).
- **Partial target evaluation.** A kept rule that also lists unsupported selectors
  (for example `XML:/*`) evaluates against its supported targets only. Named and
  negated selectors of supported variables ARE honored: `REQUEST_HEADERS:User-Agent`
  inspects only that header, `!REQUEST_COOKIES:/__utm/` excludes matching cookies.

`resources/rules/manifest.json` records the imported release, per-level rule
counts and how many rules were dropped per reason; imports since 0.5 also
record per-severity rule counts (`ruleCountsBySeverity`).

This package hardens a PHP application but is **not** a replacement for a full WAF
deployment of the CRS.

## Updating the bundled rules

```bash
bin/crs-import --tag=v4.29.0                  # import a specific release (reproducible; preferred)
bin/crs-import --tag=v4.29.0 --sha256=<hex>   # additionally verify the tarball against a pinned hash
bin/crs-import                                # import the latest upstream release (warns: not reproducible)
bin/crs-import --source=/path/to/coreruleset --tag=v4.29.0   # offline, from a local checkout
```

The command downloads the release tarball, filters the rules as described above,
splits them per paranoia level into `resources/rules/*.plN.conf`, copies referenced
`.data` files and writes `manifest.json`. Prefer an explicit `--tag`; a bare import of
"latest" warns because it is not reproducible. `--sha256` verifies the downloaded
tarball before extraction (the computed hash is always printed so it can be pinned),
and `GITHUB_TOKEN`, if set, is sent only to the GitHub API, never with the tarball
download.

The scheduled `CRS Update` GitHub Actions workflow runs the import weekly and opens a
pull request when a new CRS release was imported. The test suite runs in that pull
request, where the required `CI passed` check gates the merge, so an import that breaks
the suite still surfaces as a reviewable PR. Because the PR is created with the workflow
`GITHUB_TOKEN`, its CI checks must be triggered manually once (close and reopen the PR).
Releases of this package are tagged manually after review.

## Development

```bash
composer install
composer test     # rector (dry-run), php-cs-fixer (dry-run), phpunit, phpstan
```

PHPUnit test suites: `Unit` (preset logic), `Engine` (the SecRule engine),
`ShippedRules` (the committed CRS import), and `Integration` (`.phpt` end-to-end).

The `ShippedRules` PHPUnit test suite validates the committed import output
(manifest consistency, every rule parses, smoke checks against known attacks).
It also runs one behavioral test **per shipped rule**: a verified attack payload
is fed through the engine and asserted to trigger exactly that rule id. Rules that
cannot be triggered through a normalized PSR-7 request (for example a newline in the
request filename) are listed as documented exceptions, so no rule is silently
untested.

The payloads live in `tests/Fixtures/rule-payloads.php` and are regenerated after an
import with:

```bash
php tools/generate-rule-payloads.php
```

The generator derives a triggering payload for each rule from its own operator
(sampling the `@rx` regex, picking phrases for `@pm`/`@pmFromFile`) and only keeps
payloads it has verified fire the rule in isolation.

## Versioning

This package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
It is still pre-1.0, so per the SemVer 0.x rules a breaking change may land in a
minor release; every such change is called out in `CHANGELOG.md`.

A change is breaking when it alters either:

- the **public PHP API** (the `Presets`, `ParanoiaLevel`, `CoreRuleSet`,
  `CoreRuleSetMatcher`, `SecRuleLoader` and related engine types), or
- the **engine behavior** - anomaly scoring, the default threshold, severity
  mapping or how rules are evaluated.

The bundled OWASP CRS rules are data, not API: updates to them ride in **minor
or patch** releases without counting as breaking, even though a new or revised
rule **can change which requests are blocked** (traffic that previously passed
may now match, and vice versa). Rule updates are always recorded in
`CHANGELOG.md`, so review it before upgrading. `Presets::crsVersion()` reports
the bundled upstream release tag.

Supported PHP versions: `>=8.2`, tested on 8.2, 8.3, 8.4 and 8.5. Security fixes
are provided for the latest minor release only (see `SECURITY.md`).

## License

The package code is dual-licensed under LGPL-3.0-or-later and a proprietary
license, like flowd/phirewall itself.

The bundled OWASP CRS rules under `resources/rules/` are a separate work:
Copyright (c) the OWASP CRS project, licensed under Apache License 2.0 (see
`resources/rules/LICENSE` and, when present, `resources/rules/NOTICE`). They are
a filtered subset of upstream CRS, reformatted per paranoia level. The Apache-2.0
terms govern the rules regardless of which license you use for the package code -
choosing the proprietary option does not relicense them.
