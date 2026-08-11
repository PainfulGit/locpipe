# locpipe

`locpipe` is a deterministic, adapter-driven Python SDK for localization
pipelines. It keeps game-specific extraction outside the core and carries
content through immutable source, translation, editorial and validation
evidence to `CONTENT_VERIFIED`.

This beta is an agent/developer SDK. It does not include a game installer,
privileged delivery hooks, network providers or a full orchestration CLI.

## Quick start

```bash
python -m venv .venv
python -m pip install dist/locpipe-0.1.0b1-py3-none-any.whl
locpipe-demo
```

The demo uses invented content, performs no network or installation work and
prints only states, counts and hashes.

Developers should start with [the architecture](docs/ARCHITECTURE.md), then
read [the adapter guide](docs/ADAPTER_GUIDE.md) and
[lifecycle contract](docs/LIFECYCLE.md). Agents must also read `AGENTS.md`.

## Support contract

- CPython 3.11, 3.12 and 3.13;
- Windows and Linux;
- exact contract wire version `0.1.0-draft.2`;
- Apache-2.0;
- trusted in-process adapters only.

Incompatible wire changes use a new versioned contract surface. Frozen v0
artifacts are never rewritten in place.
