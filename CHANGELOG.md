# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Smoke server with PING, TOOL and ASSET verbs.
- Vendored time, unicode-normalization, crossbeam-utils and memoffset behind optional features.

### Security

- 2026-02-19: Upgraded memoffset from 0.5.5 to 0.6.2 (RUSTSEC-2023-0045, GHSA-wfg4-322g-9vqv; `offset_of!` could invoke undefined behaviour).
