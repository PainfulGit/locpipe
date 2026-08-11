# Read-only adapter guide

Implement `ReadOnlyAdapterV0` with an immutable descriptor and three hooks:

1. `probe` validates the declared input format;
2. `extract` normalizes private intermediate data in the disposable work root;
3. `map` writes canonical `source_snapshot.json`, `segments.jsonl` and optional
   `relations.jsonl` to staging.

Stable IDs must derive from semantic source identity, not file order, physical
offsets or content hashes. Conditions, scripts and internal identifiers belong
in constraints or provenance, not translatable payload.

Adapters receive no project context paths and cannot publish. Use the invented
flat and structured adapters under `examples/synthetic` as conformance models.
Unknown fields and dangling relations should return machine errors before any
authoritative publication.
