# Changelog

All notable changes to this project will be documented in this file.

For per-package release history, see the [GitHub Releases](https://github.com/multivmlabs/post-quantum-packages/releases) page.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Implemented Phase 4 release hardening for `pq-algorithm-id/ts`, including cross-package compatibility tests.

### Changed

- Documented publish policy for `pq-algorithm-id`: bump exact pinned `pq-oid` dependency first, then release `pq-algorithm-id`, with no required cross-package release sequencing workflow.
- Clarified migration posture that `pq-oid` remains the low-level OID primitive layer while `pq-algorithm-id` is canonical for identifier mappings.
