# Prepared Source Cache V0 Plan

**Milestone:** M3 of the downstream production-prologue program
**Planning baseline:** `locpipe 0.2.0b5` at `ff7f3a05bb99df0c7bd3a7beaf962785a0276c9c`
**Gate:** `M3_PREPARED_SOURCE_CACHE_PLAN_REVIEWED / IMPLEMENTATION_NOT_AUTHORIZED`

## 1. Product outcome

M3 removes repeated full-corpus preparation from production translation. It is not a cache experiment and does not authorize M4, provider work, or translation.

After one cold canonical preparation, `locpipe` must:

- publish one immutable cache of an exact accepted `PreparedSourceAuthorityV0`;
- load that authority in a new process without reading the original `segments.jsonl` or `relations.jsonl`;
- create a fresh process-local binder rather than serialize or revive a binder token;
- create and validate batch scopes through prepared indexes;
- produce byte-identical scope, translation, fluency-validation, and content-validation artifacts;
- reject partial, corrupt, stale, foreign, unsupported, or ambiguously published caches;
- keep each batch path proportional to selected rows and incident relations, with no hidden total-corpus pass.

The global objective remains the first complete downstream prologue patch. M3 is accepted only when it makes the M4 foreground multi-batch session practical. The active private production plan remains the milestone authority; this document owns only the generic M3 design and acceptance sequence.

## 2. Ownership and non-goals

`locpipe` owns generic segment/relation representation, source-lock and reconciliation binding, deterministic cache publication/loading, process-local binder reconstruction, prepared scope creation, and exact canonical/prepared parity.

The downstream project later owns the approved prologue scope, horizontal waves, profiles, prompts, terminology, linguistic layer, session lifetime, ledger, approvals, provider execution, packaging, and delivery.

M3 does not add a daemon, scheduler, ledger, provider framework, retry engine, second adapter, project-specific schema, linguistic cache, package cache, or eviction policy. No downstream-project ID, text, path, terminology, count, profile, campaign rule, or private cache instance enters the public package or repository fixtures. Frozen v0 wire bytes and existing canonical outputs remain unchanged.

## 3. Accepted baseline and exact public ceiling

`0.2.0b5` already provides:

- process-local `PreparedSourceAuthorityV0` with prepared rows and five immutable indexes;
- `prepare_accepted_source_authority_v0(...)` for cold preparation;
- `rebind_prepared_source_authority_v0(...)` for exact config rebinding;
- prepared translation and content-validation builders;
- binder rejection of copying, pickling, cross-process reuse, and unsupported construction.

M3 extends this authority rather than creating a parallel prepared model.

### Exact four-symbol public API ceiling

```python
@dataclass(frozen=True, slots=True)
class PreparedSourceCacheReceiptV0:
    def canonical_bytes(self) -> bytes: ...

    @classmethod
    def from_bytes(cls, payload: bytes) -> "PreparedSourceCacheReceiptV0": ...

def build_prepared_source_cache_v0(
    authority: PreparedSourceAuthorityV0,
    destination_parent: Path,
    *,
    producer_distribution_sha256: str,
) -> PreparedSourceCacheReceiptV0:
    ...

def load_prepared_source_authority_v0(
    cache_root: Path,
    *,
    expected: PreparedSourceCacheReceiptV0,
) -> PreparedSourceAuthorityV0:
    ...

def freeze_scope_prepared_v0(
    authority: PreparedSourceAuthorityV0,
    entries: tuple[ScopeEntryV0, ...],
    *,
    target_locales: tuple[str, ...],
    config_snapshot_sha256: str,
) -> FrozenScopeV0:
    ...
```

`freeze_scope_prepared_v0` is required, not optional. Without it, M4 would call canonical `freeze_scope_v0`, which builds a full segment set and scans all relations for every scope. The prepared facade must reuse the existing `_accept_scope_v0` semantics and prepared indexes, return the exact same `FrozenScopeV0`, and yield byte-identical `scope.json` and `scope_lock.json` through `frozen_scope_artifacts_v0`.

No public manifest model, inspection facade, callback, diagnostic stage enum, new error enum, or public module is added. Cache parsing and binder reconstruction remain private implementation details behind `locpipe.content.v0`.

## 4. Cache authority and receipt

V0 is a cache of one exact accepted base `PreparedSourceAuthorityV0`, not a config-independent structural cache. Its identity therefore includes the base config-bound source lock, corpus digest, reconciliation, and any accepted reconciliation history. Different base authorities may have different cache IDs even when their raw corpus bytes match.

The returned receipt is stored by the host outside the cache and is the loader's trust anchor. Reading an expected receipt from the cache itself is forbidden.

The closed receipt contains:

- cache contract/version and `cache_id`;
- `manifest_sha256`;
- exact `locpipe` version and caller-supplied producer distribution/wheel SHA-256;
- adapter ID, version, and digest;
- base source-lock SHA-256, reconciliation SHA-256, and corpus digest;
- snapshot, segments, and relations SHA-256 or explicit relation absence;
- segment, relation, and file counts;
- total cache bytes.

It contains no paths, timestamps, timings, payload, or diagnostic state. The wheel hash is external caller authority; the installed package cannot self-authenticate it.

`cache_id` is the SHA-256 of a canonical closed manifest identity projection that excludes `cache_id`, excludes the receipt-only `manifest_sha256`, and excludes external filesystem paths. The projection includes package/distribution identity, exact base authority hashes, source/adapter binding, fixed shard-format constants, and the sorted relative inventory with lengths, counts, and hashes.

### Exact receipt contract

`PreparedSourceCacheReceiptV0` has exactly these fields, in this dataclass order:

```python
cache_id: str
manifest_sha256: str
locpipe_version: str
producer_distribution_sha256: str
adapter_id: str
adapter_version: str
adapter_digest: str
config_snapshot_sha256: str
source_lock_sha256: str
reconciliation_sha256: str
corpus_digest: str
snapshot_sha256: str
segments_sha256: str
relations_sha256: str | None
segment_count: int
relation_count: int
file_count: int
total_bytes: int
```

All SHA values are lowercase 64-hex strings; strings are exact non-empty `str` values; counts are exact nonnegative `int` values and reject `bool`. Its canonical `as_dict()` projection adds only `"contract": "locpipe.content.prepared-source-cache-receipt/v0"` and the fields above. `canonical_bytes()` emits that closed projection as RFC 8785 JSON plus one LF. `from_bytes()` is the durable host restart seam and rejects noncanonical bytes, unknown contracts, and missing or extra fields without requiring the host to duplicate the schema.

### Exact manifest contract

`manifest.json` is RFC 8785 canonical JSON plus LF with exactly:

```text
contract: "locpipe.content.prepared-source-cache-manifest/v0"
schema_version: "0.1.0"
cache_id: lowercase SHA-256
producer: {
  locpipe_version: non-empty string,
  distribution_sha256: lowercase SHA-256
}
source: {
  adapter_id: non-empty string,
  adapter_version: non-empty string,
  adapter_digest: lowercase SHA-256,
  config_snapshot_sha256: lowercase SHA-256,
  source_lock_sha256: lowercase SHA-256,
  reconciliation_sha256: lowercase SHA-256,
  corpus_digest: lowercase SHA-256,
  snapshot_sha256: lowercase SHA-256,
  segments_sha256: lowercase SHA-256,
  relations_sha256: lowercase SHA-256 or null,
  source_locale: non-empty string,
  source_version: non-empty string
}
format: {
  encoding: "UTF-8",
  record_framing: "RFC8785_JSON_LF",
  prepared_shard_target_bytes: 8388608,
  shard_name_digits: 6,
  indexes: "REBUILD_ON_LOAD"
}
counts: {
  segments: nonnegative integer,
  relations: nonnegative integer
}
aggregates: {
  prepared_segments_sha256: lowercase SHA-256,
  prepared_relations_sha256: lowercase SHA-256
}
files: ordered list of {
  role: one of SOURCE_LOCK, RECONCILIATION, RAW_SEGMENTS,
        RAW_RELATIONS, PREPARED_SEGMENTS, PREPARED_RELATIONS,
  path: safe relative POSIX UTF-8 path,
  byte_length: nonnegative integer,
  record_count: nonnegative integer,
  sha256: lowercase SHA-256
}
```

`prepared_*_sha256` hashes the bytewise concatenation of prepared canonical record bytes in logical order and is the SHA-256 of empty bytes for an empty family. `files` excludes `manifest.json`, so no recursive manifest hash exists. `file_count` in the external receipt is `len(files) + 1`; `total_bytes` is the manifest byte length plus all declared file lengths.

`cache_id = raw_sha256(canonical_json_bytes(manifest_without_cache_id))`. The loader recomputes it exactly, then requires the final directory basename and external receipt value to match. The external receipt's `manifest_sha256` is the raw SHA-256 of final `manifest.json` bytes.

Batch-specific config changes do not create new cache files. Under accepted b5 semantics, however, `rebind_prepared_source_authority_v0` performs `reconcile_sources_v0` and serializes an `O(S)` reconciliation. Therefore:

- M4 uses one exact campaign/session config snapshot in its normal batch loop;
- rebind is allowed only at a distinct session/config boundary, never per batch;
- one current rebound authority is retained and reused by all batches under that config;
- old rebound authorities are released before replacement;
- if production requires a unique config digest per batch, M3 stops for a new authority design rather than hiding `O(S)` work or building one cache per batch.

Multi-config parity remains a compatibility test, not a performance claim.

## 5. Exact V0 storage format

The cache is private and source-bearing. It intentionally keeps exact accepted raw bytes and a prepared representation on disk. This duplication preserves downstream byte authority while avoiding reparsing complex canonical envelopes during warm load. It must be measured honestly.

```text
<cache-id>/
  manifest.json
  authority/
    source-lock.json
    reconciliation.json
  raw/
    segments.jsonl
    relations.jsonl
  prepared/
    segments/000000.jsonl
    ...
    relations/000000.jsonl
    ...
```

`raw/relations.jsonl` is absent only when relation authority is canonically absent.

Rules:

- Source-lock, reconciliation, and raw files are exact accepted bytes.
- Prepared segment records contain the fields needed to reconstruct both `SourceSegmentV0` and `PreparedSourceSegmentV0` without parsing raw segment envelopes.
- Prepared relation records contain canonical envelope bytes and existing prepared projections needed to reconstruct compatibility and prepared relation rows.
- Indexes are not serialized. The existing private binder rebuilds all five indexes once with `indexes=None`.
- Prepared records are canonical UTF-8 RFC 8785 JSON followed by one LF.
- Segments are ordered by stable ID; relations by semantic digest.
- Target prepared-shard payload is 8 MiB. A non-empty shard closes before the next record would exceed 8 MiB. A single oversized record occupies one shard and does not create a production rejection cap.
- Shards use six-digit zero-based names.
- An empty relation set has no relation shards and explicit canonical absence in the manifest.
- Inventory is sorted by relative POSIX UTF-8 path and contains exactly role, path, byte length, record count, and SHA-256.
- Raw files have record counts and exact hashes but are not reparsed into source envelopes on warm load.
- No timestamp, PID, absolute path, random value, Python hash order, or diagnostic datum enters authoritative bytes.
- Two builds in fresh processes with different `PYTHONHASHSEED` values produce byte-identical inventories and manifest bytes.

Prepared segment records have exactly:

```text
contract: "locpipe.content.prepared-source-segment-cache/v0"
identity: exact BranchIdentityV0 object
content_type: non-empty string
source_revision_sha: lowercase SHA-256
locator_sha256: lowercase SHA-256
payload: any accepted canonical JSON value
constraints: any accepted canonical JSON value
```

`payload_bytes` and `constraints_bytes` are reconstructed with `canonical_value_bytes`; `text_payload` is derived only when `payload` is an exact string. The record is rejected unless the reconstructed `PreparedSourceSegmentV0` passes its existing constructor, identity/locale matches the source lock, and the ordered stable-ID and revision aggregate matches the manifest/source authority.

Prepared relation records have exactly:

```text
contract: "locpipe.content.prepared-source-relation-cache/v0"
digest: lowercase SHA-256
relation_type: non-empty string
envelope: exact canonical relation JSON object
branch_ids: sorted unique list of stable-ID strings
logical_ids: sorted unique list of non-empty string lists
```

`envelope_bytes` is reconstructed with `canonical_json_bytes`. Existing `PreparedSourceRelationV0` validation must reproduce `digest`; relation type, endpoints, branch/logical projections, locale, and source-lock membership are recomputed from the envelope and must equal the stored projections. JSON values are embedded canonical values, never base64 or implementation-specific byte serialization.

Warm load still performs `O(cache bytes + S + R)` parsing and validation once per process. "Zero warm corpus reads" means zero access to the original corpus root, not zero cache I/O or zero parsing.

## 6. Binder reconstruction

No PID, object identity, weak reference, registry entry, binder token, mapping proxy, pickle, marshal object, database implementation bytes, or native memory dump is serialized.

The loader:

1. Parses the exact source lock with the existing strict parser.
2. Uses one new private closed `SourceReconciliationV0` parser that preserves exact reconciliation bytes and legitimate previous/events/tombstones/target-validity history.
3. Streams and validates prepared rows and relation envelopes.
4. Reconstructs `LoadedSourceCorpusV0`, prepared rows, and cross-bindings without reading or parsing the original raw corpus.
5. Validates accepted source revision hashes, stable IDs against source-lock branch IDs, and recomputed relation branches/locales and aggregate digests.
6. Calls the existing private binder exactly once with indexes omitted so it rebuilds them.
7. Returns only after existing binder validation succeeds.

The loader must not call `reconcile_sources_v0` to rebuild persisted reconciliation because that can lose accepted history. Long-session tests prove weakref cleanup and no monotonic binder-registry growth; the foreground session retains the base authority strongly and at most one current rebound authority.

## 7. Manifest-last no-clobber publication

Portable atomic replacement of a non-empty directory is not assumed.

1. Validate authority, distribution SHA, and destination parent before creating output.
2. The host verifies that the parent is an approved private root. Generic `locpipe` traverses every existing component with `os.lstat`, rejects `stat.S_ISLNK`, and on Windows rejects `st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT`; it then verifies exact resolved descendant containment and case-fold-unique relative names.
3. Create staging with `tempfile.mkdtemp(prefix=".locpipe-cache-staging-", dir=destination_parent)`. Every staged file uses `os.open(..., os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY, 0o600)` on Windows and the equivalent flags without `O_BINARY` elsewhere. Stream writes, call `file.flush()`, then `os.fsync(file.fileno())`. Compute the final `cache_id`.
4. Derive the final basename exactly from `cache_id`; staging names can never satisfy final-name grammar.
5. Exclusively create the absent final cache directory with `os.mkdir(final_root, 0o700)`; `FileExistsError` is a collision. Never replace, delete, repair, or steal a pre-existing final root.
6. Open every staged source once with `os.open(..., os.O_RDONLY | os.O_BINARY)` and `O_NOFOLLOW` where available, then compare `os.fstat` with the prior `os.lstat`. Stream from that same handle while hashing, counting, framing/parsing, and writing the final file through an exclusive `os.open(... O_EXCL ...)` handle. Flush and `os.fsync` each final file. No verified bytes are later substituted through a reopened source.
7. Publish `manifest.json` last through the same exclusive file-create, write, flush, and `os.fsync` sequence. A valid manifest is the sole commit marker.
8. Re-read the manifest and verify complete final inventory before returning the external receipt.

The loader requires `cache_root.name == manifest.cache_id`, exact declared inventory, and regular non-reparse files. Missing/noncanonical manifest, partial final root, extra/missing file, or inventory mismatch is rejected as incomplete.

Hash, count, framing, and parse checks use the same opened bytes; there is no verify-then-reopen trust gap. In-process failure removes only staging/final state proven created by that invocation. Crash residue remains invalid and requires explicit host cleanup; no automatic repair or lock stealing is added.

POSIX opens the final directory and destination parent with `os.open(..., os.O_RDONLY | os.O_DIRECTORY)` and calls `os.fsync` after final-file creation and manifest publication. On Windows, `os.fsync` maps the file descriptor commit to the platform file flush; Python 3.11 provides no portable directory fsync, so the contract guarantees fail-closed namespace acceptance and file-content flushing but does not claim directory-entry durability across sudden power loss. Any unsupported flag or flush failure fails publication before a receipt is returned. Cleanup uses only `shutil.rmtree` on staging/final directories whose creation ownership is retained in local state and whose resolved paths remain exact children of the destination parent.

## 8. Complexity and memory model

Let `S` be source segments, `R` relations, `C` cache bytes, and `s + r` one selected scope plus incident relations.

| Operation | Required complexity | Frequency |
|---|---:|---:|
| Canonical cold prepare | `O(S + R)` | Once per accepted base authority |
| Cache build/verification | `O(S + R + C)` | Once per accepted base authority |
| Fresh-process warm load | `O(C + S + R)` | Once per foreground process |
| Config rebind under b5 | `O(S)` plus `O(S)` reconciliation bytes | Session/config boundary only |
| Prepared scope freeze | `O(s + r)` | Per batch scope |
| Translation/validation materialization | `O(s + r)` | Per batch |

No batch-loop call graph may invoke rebind, reconciliation, total-corpus iteration, or total-corpus hashing. Tests instrument actual iterators/parser boundaries, not wrapper assertions.

### Retention model

| Phase | Required retained state | Bounded transient state |
|---|---|---|
| Cold build | Existing raw bytes, compatibility graph, prepared graph, five indexes | One prepared shard buffer plus manifest metadata |
| Warm load | Exact raw segments/relations bytes, compatibility graph, prepared graph, rebuilt indexes | One prepared shard, one raw-file read/copy transient, parser state |
| Steady session | Loaded base authority and at most one current rebound authority sharing large rows/indexes | Selected batch artifacts only |

The implementation identifies the sole owner of every payload buffer and defines exact LF/framing reconstruction. It never retains all shard buffers simultaneously or concatenates through an avoidable second full-size temporary buffer.

Unit tests enforce operation counts and asymptotic topology, not wall-clock timing. M3C reports wall time, cache size, RSS, and tracemalloc separately. Before M3B, Engineering proposes explicit host acceptance budgets from the known machine and prior cold evidence; Orchestrator approves them. Required hard gates are:

- zero total-corpus iteration per batch;
- exactly one warm load per foreground process;
- no semantic preparation repeated per batch;
- full-session benchmark covers load once plus all representative batch materializations;
- warm time and peak RSS satisfy the approved absolute or cold-relative budget.

The approved M3C host gates are fixed now:

- Measurement host is the same Windows machine, exact CPython 3.11.9, exact candidate wheel, a short local NTFS root, and no concurrent project build.
- `perf_counter_ns()` measures one canonical cold preparation and two independent fresh-process warm loads. The maximum of the two warm values must be at most `min(600 seconds, 0.50 * cold_prepare_seconds)`.
- A full M4-like pass in each warm process measures every representative and worst-scope freeze/materialization. Every batch operation must finish within 30 seconds and operation counters must still prove `O(s + r)`; timing never excuses a topology violation.
- An external monitor retains the Windows process handle through completion and reads `GetProcessMemoryInfo(...).PeakWorkingSetSize` for the hard gate. Each warm process peak must be at most 4 GiB and at most `1.10 * cold_prepare_peak_RSS`. Optional 250 ms `WorkingSetSize` samples may describe the memory curve but cannot decide the gate. In-process `tracemalloc` is reported separately and is not substituted for RSS.
- Cache disk bytes are the exact sum of all final regular-file lengths. They must be at most `min(3 GiB, 2.25 * accepted_raw_authority_bytes + 64 MiB)`, where raw authority bytes are source lock, reconciliation, segments, and present relations.
- Both warm runs must independently pass all byte-parity and no-original-read gates. No averaging can hide one failing run.

If raw-plus-prepared disk duplication or baseline steady-state memory exceeds the approved budget, M3 stops for architecture review. Lazy, mmap, streaming-authority, or cap increases are not introduced silently.

## 9. Bounded diagnostics

Diagnostics serve M3 and remain outside cache identity.

The public API exposes no callback, stage enum, diagnostic journal, retry protocol, or diagnostic subprocess. Benchmark tooling measures stage durations/RSS externally. The receipt contains only authoritative counts, bytes, and hashes.

Cache failures use existing `ContractViolation` and `ErrorCode` values with stable non-payload details:

- `SCHEMA_UNKNOWN` or `SCHEMA_VERSION_UNSUPPORTED`: manifest contract/version;
- `MALFORMED_ARTIFACT`: canonical framing, closed fields, incomplete inventory;
- `PATH_ESCAPE`: unsafe path, symlink, junction, or reparse escape;
- `HASH_MISMATCH`: byte length, hash, order, or aggregate mismatch;
- `BINDING_MISMATCH`: expected receipt, package, adapter, source, or reconciliation mismatch;
- `DUPLICATE_IDENTITY`: duplicate file or row identity;
- `OUTPUT_CONTRACT_VIOLATION`: destination collision or publication contract.

Errors do not include payload text, secrets, or unrestricted absolute paths. No observer can turn successful publication into an ambiguous failure because there is no public callback.

## 10. Exact implementation ceiling

Public API ceiling: exactly the four symbols in Section 3. One private strict reconciliation parser may live in `_cache.py`. No new public module.

Total ceiling is 13 files: 12 handwritten plus one generated.

1. `docs/PREPARED_SOURCE_CACHE_V0_PLAN.md`
2. `src/locpipe/content/v0/_cache.py`
3. `src/locpipe/content/v0/_scope.py`
4. `src/locpipe/content/v0/__init__.py`
5. `tests/test_prepared_source_cache_v0.py`
6. `tests/test_installed_wheel_checker.py`
7. `tools/check_installed_wheel.py`
8. `README.md`
9. `docs/ARCHITECTURE.md`
10. `docs/SECURITY_MODEL.md`
11. `CHANGELOG.md`
12. `pyproject.toml`
13. `PUBLIC_EXPORT_MANIFEST.json` (generated)

No CI workflow or `RELEASE_POLICY.md` change is planned because current CI already covers discovered tests, canonical parity, public-boundary, reproducibility, package, installed-wheel, SBOM, and release metadata gates. Exceeding this ceiling requires pre-implementation architecture review and a concrete gap.

## 11. M3A planning closure

This reviewed document closes M3A. No additional planning or permission checkpoint is required before an authorized M3B.

During M3B, Engineering maintains the requirement-to-code-to-test mapping with exact private helper and test names and follows the generated-manifest sequence. This is part of the bounded implementation checkpoint, not a separate gate. Any semantic change to the approved public API, schemas, publication model, or budgets returns to Orchestrator architecture review.

M3A read no private corpus and changed no production code.

## 12. M3B synthetic implementation cycle

After M3A Orchestrator acceptance, Engineering implements one bounded checkpoint with a normal synthetic `test -> fix -> retest` cycle.

Required invented-fixture evidence:

1. Fresh-process builds with different hash seeds are byte-identical file-for-file.
2. Warm load succeeds in a fresh process and creates a new valid binder.
3. Copy, pickle, forge, mutate, and cross-process authority use remains rejected.
4. Canonical and prepared scope objects/artifacts are byte-identical, including after an exact session-boundary rebind.
5. Canonical-cold and cache-warm translation jobs, packets, handoffs, and terminal reconstruction are byte-identical.
6. Canonical-cold and cache-warm content-validation jobs and both prepared fluency provenance paths are byte-identical.
7. Original corpus paths are absent or guarded by fail sentinels during warm load and all warm operations.
8. Unknown schema, foreign receipt/package/adapter/source/reconciliation, corruption, truncation, extra/missing/duplicate file or row, wrong order, partial final root, and index mismatch fail closed.
9. Shard tests cover exact 8 MiB boundary, oversized record, empty relations, LF/framing, six-digit names, and sorted inventory.
10. Existing final collisions remain untouched; owned staging/final cleanup is bounded; manifest-last acceptance is proven on supported Windows/POSIX semantics.
11. A realistic sparse/overlapping graph proves one cold parse, one warm load per process, prepared keyed scope closure, no per-batch rebind/reconcile/full iteration, and bounded shard buffers.
12. A long synthetic session proves rebound-authority release and no binder-registry growth.
13. Existing v0 canonical fixtures remain byte-identical and all active `locpipe` tests pass.

The Orchestrator performs one findings-first code review after the complete checkpoint. Engineering receives one consolidated correction set. Unresolved P0/P1 returns to architecture review rather than a chain of micro-diagnostics.

## 13. M3B clean-wheel prerelease acceptance

After M3B code review is green, prepare one `locpipe 0.2.0b6` prerelease
candidate with future tag contract `v0.2.0-beta.6`. Build reproducible
wheel/sdist evidence in clean CPython 3.11.9, verify the four public cache and
prepared-scope symbols, build and load one small invented cache after removing
its original invented source files, and prove exact prepared-scope and existing
translation/validation parity. Corruption, foreign-receipt,
partial-publication and binder-copy probes run only against invented or copied
cache roots and must fail closed.

This package checkpoint contains no full-corpus runner, campaign controller,
project adapter, performance harness or source-specific authority. Package
identity, commit or local package evidence does not authorize publication.

## 14. Release, downstream acceptance, and close

The required order is:

1. Complete Orchestrator review of the generic b6 checkpoint.
2. Commit the reviewed bytes and reproduce wheel, sdist, release metadata and
   clean installed-wheel evidence from that exact commit.
3. Obtain explicit user authorization before publishing one immutable b6
   prerelease, then verify fresh-download hashes.
4. Separately migrate the downstream repository to the exact published wheel
   URL, version and SHA without source fallback, and prove installed origins and
   all four cache/scope symbols.
5. Implement and review the downstream full-corpus acceptance worker under the
   declared b6 dependency.
6. Under separate execution authorization, prove one cold parse, one cache
   build, two fresh-process warm loads, direct cold/warm artifact byte parity,
   actual source-open/parser counts, phase-specific durations, external peak
   RSS and copied-state failure probes.
7. Run the downstream guarded, boundary and migration gates before recording
   `M3_COMPLETE / M4_NOT_AUTHORIZED`.

Full-corpus inputs, cache and external receipts remain outside Git under an
approved ignored root. M4 does not start automatically, and no second release
fills avoidable API omissions discovered after publication.

## 15. Stop rules

Stop for architecture review if:

- downstream-project-specific semantics enter `locpipe`;
- a binder token or implementation object must be serialized;
- accepted canonical bytes change;
- warm scope/translation/validation reads original source files;
- a batch-loop path performs total-corpus iteration, hashing, rebind, or reconciliation;
- production requires unique config authority per batch;
- cache output is nondeterministic or cannot be accepted manifest-last without clobber;
- provenance cannot distinguish base-authority drift;
- corruption or partial publication can be accepted;
- diagnostics require raw payload or a persistence framework;
- raw/prepared duplication or memory exceeds approved budgets;
- M3 expands into M4 session state, ledger, linguistic policy, provider work, or packaging;
- the checkpoint cannot show reduced time-to-first-production-prologue patch.

## 16. Traceability matrix

M3A replaces implementation placeholders with exact symbols/tests before authorization.

| Requirement | Planned implementation | Required evidence |
|---|---|---|
| One cold canonical parse | `_cache._validate_authority`, `_cache._manifest_value` | `PreparedSourceAuthorityV0Tests.test_prepare_parses_source_once_and_repeated_prepared_builds_do_not_reparse` |
| Deterministic immutable cache | `_cache._stage_shards`, `_cache._stage_cache`, `_cache._publish` | `PreparedSourceCacheV0Tests.test_cache_is_deterministic_and_rebuilds_equivalent_authority` |
| External cache authority | `PreparedSourceCacheReceiptV0.canonical_bytes`, `PreparedSourceCacheReceiptV0.from_bytes`, `_cache._receipt` | `PreparedSourceCacheV0Tests.test_receipt_canonical_roundtrip_and_closed_parser` |
| Zero original warm reads | `load_prepared_source_authority_v0`, `_cache._declared_payload` | `PreparedSourceCacheV0Tests.test_load_works_in_fresh_process_and_binder_is_process_local`, `test_cache_warm_content_validation_is_exact_and_keyed`, `test_cache_warm_fluency_initial_and_correction_paths_are_exact_and_keyed` |
| Fresh binder | `load_prepared_source_authority_v0`, `_bind_prepared_source_authority_v0` | `PreparedSourceCacheV0Tests.test_load_works_in_fresh_process_and_binder_is_process_local` |
| Prepared scope parity | `_scope.freeze_scope_prepared_v0`, `_scope._prepared_scope_access_v0` | `PreparedSourceCacheV0Tests.test_cache_is_deterministic_and_rebuilds_equivalent_authority`, `test_prepared_scope_uses_prebuilt_relation_indexes` |
| Translation parity | Existing `build_translation_job_prepared_v0` facade over cold or loaded authority | `PreparedSourceCacheV0Tests.test_cache_is_deterministic_and_rebuilds_equivalent_authority` |
| Validation/fluency parity | Existing prepared validation facades over a cache-loaded binder | `PreparedSourceCacheV0Tests.test_cache_warm_content_validation_is_exact_and_keyed`, `test_cache_warm_fluency_initial_and_correction_paths_are_exact_and_keyed` |
| Session config invariant | M4 consumer contract and existing rebind boundary | No rebind/reconcile in batch-loop test |
| Corruption/partial rejection | `_cache._read_and_validate_inventory`, `_cache._parse_reconciliation`, `_cache._parse_prepared_rows` | `PreparedSourceCacheV0Tests.test_collision_receipt_corruption_and_inventory_fail_closed`, `test_reconciliation_parser_rejects_semantic_history_mutations`, `test_cross_shard_relation_reorder_fails_closed` |
| Bounded memory | `_cache._stage_shards` writes one shard before reuse; indexes rebuilt by `_bind_prepared_source_authority_v0` | `PreparedSourceCacheV0Tests.test_missing_manifest_sharding_and_registry_cleanup` |
| No per-batch full pass | Lookup-only prepared indexes in loaded scope, translation, content validation, and fluency validation | `PreparedSourceCacheV0Tests.test_cache_is_deterministic_and_rebuilds_equivalent_authority`, `test_cache_warm_content_validation_is_exact_and_keyed`, `test_cache_warm_fluency_initial_and_correction_paths_are_exact_and_keyed` |
| Stable bounded failures | `_cache._cleanup_owned` and existing `ErrorCode` mapping | `PreparedSourceCacheV0Tests.test_owned_cleanup_attempts_all_roots_and_has_stable_failure`, `test_staging_cleanup_failure_removes_owned_final_and_is_stable`, `test_final_verification_cleanup_failure_after_manifest_is_stable` |
| Release completeness | Docs, checker, package, generated manifest | Reproducible b6 and installed-wheel proof |
| Production handoff | Exact Slice03 dependency migration | Guarded active suite and M3 gate |

## 17. Review and authorization

This revision incorporates Engineering and independent architecture review findings, including both P0 issues: hidden `O(S)` config rebinding and missing prepared scope creation. A final review pass reports only unresolved P0/P1 gaps against this revision.

If no unresolved P0/P1 remains, the gate becomes:

`M3_PREPARED_SOURCE_CACHE_PLAN_REVIEWED / IMPLEMENTATION_NOT_AUTHORIZED`

Implementation requires separate user authorization. This plan authorizes no private corpus read, code implementation, package version change, release, publication, Slice03 migration, or M4 work.
