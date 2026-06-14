# Phirewall OWASP Core Rule Set

OWASP [Core Rule Set (CRS)](https://github.com/coreruleset/coreruleset) support for
[flowd/phirewall](https://github.com/flowd/phirewall), the PSR-7/PSR-15 PHP firewall.

This package provides two things:

1. **The ModSecurity SecRule engine** (`Flowd\PhirewallPresetOwaspCrs\Engine\`) - a parser and
   evaluator for ModSecurity-style `SecRule` directives, usable with any
   ruleset. It was extracted from the core `flowd/phirewall` package in 0.6.
2. **Ready-made CRS presets** - a pre-filtered, per-paranoia-level snapshot of
   the CRS request rules, exposed as `Config` overlays:
   - **Blocklist preset** - block every request that matches a CRS rule.
   - **Fail2Ban preset** - count CRS matches per client IP and ban repeat offenders.

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

Prefer banning probing clients over blocking single requests? Use the fail2ban preset:

```php
$config = $config->with(
    Presets::fail2ban(ParanoiaLevel::Level1, threshold: 5, period: 600, ban: 3600),
);
```

For manual wiring (custom rule name, enabling/disabling single CRS rule ids), get the
raw rule set:

```php
use Flowd\Phirewall\Config\Rule\BlocklistRule;
use Flowd\PhirewallPresetOwaspCrs\Engine\CoreRuleSetMatcher;

$coreRuleSet = Presets::coreRuleSet(ParanoiaLevel::Level2);
$coreRuleSet->disable(942100);
$config->blocklists->addRule(new BlocklistRule('my-crs-rule', new CoreRuleSetMatcher($coreRuleSet)));
```

`Presets::crsVersion()` returns the bundled upstream release tag.

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
higher levels detect more but produce more false positives. Since Phirewall blocks on
the first match (there is no anomaly scoring, see below), be conservative: start with
level 1, or pair higher levels with the fail2ban preset instead of the blocklist.

## What is included (and what is not)

Phirewall's SecRule engine implements a pragmatic subset of ModSecurity. The import
process therefore ships only the CRS rules that the engine can evaluate faithfully:

| Filter | Effect |
| --- | --- |
| Request phase only | `RESPONSE-*.conf` files and exclusion templates are skipped |
| Blocking rules only | Rules without a `deny`/`block` action (initialization, scoring) are dropped |
| No chains | Chained rules are dropped entirely; keeping only a chain's first condition would over-block |
| Supported operators | `@rx`, `@contains`, `@streq`, `@beginsWith`, `@endsWith`, `@pm`, `@pmFromFile`; everything else (`@detectSQLi`, `@validateByteRange`, ...) is dropped |
| Supported variables | `REQUEST_URI`, `REQUEST_METHOD`, `QUERY_STRING`, `ARGS`, `ARGS_NAMES`, `REQUEST_COOKIES`, `REQUEST_COOKIES_NAMES`, `REQUEST_HEADERS`, `REQUEST_HEADERS_NAMES`, `REQUEST_FILENAME`; rules whose variables are all unsupported (for example selector variables such as `REQUEST_HEADERS:User-Agent`) are dropped |

Further engine differences to be aware of:

- **No anomaly scoring.** Upstream CRS collects per-rule scores and blocks at a
  threshold; Phirewall blocks on the first matching rule.
- **No transformations.** `t:lowercase`, `t:urlDecodeUni` and friends are ignored;
  rules are evaluated against the raw collected values.
- **Partial variable evaluation.** A kept rule that also lists unsupported variables
  (for example a `!REQUEST_COOKIES:/__utm/` exclusion) evaluates against its
  supported variables only.

`resources/rules/manifest.json` records the imported release, per-level rule counts
and how many rules were dropped per reason.

This package hardens a PHP application but is **not** a replacement for a full WAF
deployment of the CRS.

## Updating the bundled rules

```bash
bin/crs-import                 # import the latest upstream release
bin/crs-import --tag=v4.16.0   # import a specific release
bin/crs-import --source=/path/to/coreruleset --tag=v4.16.0   # offline, from a local checkout
```

The command downloads the release tarball, filters the rules as described above,
splits them per paranoia level into `resources/rules/*.plN.conf`, copies referenced
`.data` files and writes `manifest.json`.

The scheduled `CRS Update` GitHub Actions workflow runs the import weekly, executes
the test suite against the regenerated rules and opens a pull request when a new CRS
release was imported. Releases of this package are tagged manually after review.

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

## License

The package code is dual-licensed under LGPL-3.0-or-later and a proprietary
license, like flowd/phirewall itself.

The bundled OWASP CRS rules under `resources/rules/` are a separate work:
Copyright (c) the OWASP CRS project, licensed under Apache License 2.0 (see
`resources/rules/LICENSE` and, when present, `resources/rules/NOTICE`). They are
a filtered subset of upstream CRS, reformatted per paranoia level. The Apache-2.0
terms govern the rules regardless of which license you use for the package code -
choosing the proprietary option does not relicense them.
