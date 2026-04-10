# Security notes

This repository is a deliberately vulnerable smoke target. It is never deployed, so there is no
disclosure process. The entries below record the issues that were fixed in this history, so that
the record of what changed and why is in one place.

## 2026-03-16: path traversal in `read_asset` (CWE-22)

The `ASSET` verb joined the client-supplied name onto the asset root and read the result, so a
name containing `../` read files outside the asset directory. `read_asset` now canonicalises the
joined path with `std::fs::canonicalize` and refuses any result that does not start with the
asset root.

## 2026-03-06: command injection in `run_maintenance` (CWE-78)

The `TOOL` verb built a shell command line from the client-supplied tool name and ran it through
`sh -c`, so shell metacharacters in the name ran arbitrary commands. `run_maintenance` now accepts only
the names `status` and `version` and answers them directly; there is no command and no shell.

## 2026-02-19: memoffset 0.5.5 (RUSTSEC-2023-0045)

memoffset 0.5.5 computed field offsets by dereferencing an uninitialised value in `offset_of!`,
which is undefined behaviour (GHSA-wfg4-322g-9vqv). The optional dependency was upgraded to
0.6.2, which computes offsets through `addr_of!`.
