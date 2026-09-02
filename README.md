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
python -m build --no-isolation --outdir dist
python -m pip install "dist/locpipe-<version>-py3-none-any.whl"
locpipe-demo
```

Replace `<version>` with the exact fresh wheel filename produced from this
checkout. This checkout declares package identity `0.2.0b4` and reserves
`v0.2.0-beta.4` as its future annotated-tag contract. The `0.2.0b3`
prerelease remains immutable and contains parsed-source authority rebinding but
predates the prepared source facade. The `0.2.0b2` prerelease remains immutable
and contains the public pure translation-terminal reconstruction facade, while
`0.2.0b1` prerelease remains the published fluency baseline.
The historical `0.1.0b1` wheel predates the fluency lifecycle described below.
Package identity alone does not authorize a tag, upload or external
publication; consult the repository release page for external availability.

The demo uses invented content, performs no network or game installation work
and prints only states, counts and hashes. It exercises both a no-findings
target-only fluency review and one bounded accuracy correction plus target-only
recheck before the existing validation path reaches `CONTENT_VERIFIED`.

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

The additive `rebind_source_authority_v0` facade can bind an already parsed
source corpus to another exact configuration snapshot without a filesystem
reread or canonical segment/relation reparse. It returns fresh config-bound
source-lock and reconciliation authority while reusing the immutable parsed
segment and relation tuples; stale or foreign reconciliation authority is
rejected and prior reconciliation history is not copied by assumption.

The additive prepared source facade accepts the same immutable source authority
once, retains one prepared row layer with identity-sharing indexes, and exposes
prepared translation and content-validation entrypoints with exact canonical
parity. Warm work is bounded by the selected scope and its incident dependencies.
It is a trusted-process contract: ordinary unsupported construction, copying,
pickling, cross-process use and top-level substitution fail closed, while
deliberate same-process mutation through private mechanisms is outside scope.

Target-only fluency review is additive. Every requested target ID receives an
explicit outcome, findings cannot replace target bytes, correction is performed
only through the existing source-aware editorial overlay, and a finite policy
prevents automatic retry loops. The synthetic demo is package evidence, not a
claim about provider quality, project language policy, game integration or
release readiness.
