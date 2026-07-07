# Changelog

All notable changes to this package are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Changed

- **BREAKING (behavioural): the fail2ban preset now blocks every CRS match, not only the one that reaches the threshold.** This follows the fail2ban semantics change in phirewall 0.8: a CRS match marks a request as malicious, so `Presets::fail2ban()` now blocks every match with a 403. A match below the threshold blocks and counts (dispatching `Fail2BanMatched`); the threshold-th match within the period additionally bans the client key (dispatching `Fail2BanBanned`), so all further traffic from that key is blocked until the ban expires. Under 0.7 a match below the threshold passed through and only counted, so the preset acted as a slow counter. There is no migration for CRS traffic: a CRS filter only matches unambiguously malicious requests, so blocking them immediately is intended. The blocklist preset (`Presets::blocklist()`) is unchanged.
- Require `flowd/phirewall` `^0.8.0` (was `^0.6`); the fail2ban semantics above ship with 0.8.
