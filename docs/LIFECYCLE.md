# Content lifecycle

```text
adapter corpus
  -> source lock
  -> reconciliation
  -> frozen owned/context scope
  -> translation job and immutable submission
  -> accepted target candidates
  -> optional editorial overlay and bounded rework
  -> target-only fluency review
  -> optional exact-ID accuracy correction and target-only recheck
  -> deterministic locale validation
  -> locale receipts
  -> CONTENT_VERIFIED
```

Source changes invalidate dependent targets. Context rows are readable but
cannot enter target sets. Raw provider and editor outputs remain immutable;
accepted corrections are separate overlays.

Content findings may request at most the configured bounded rework. Schema,
scope, hash, receipt, config or provider drift fails closed and is never treated
as a translation issue.

Fluency review requires one explicit `NO_FINDINGS` or `FINDINGS` decision for
every requested ID. Its packet contains candidate target bytes and allowlisted
target-side projection data, not source payload or constraints. Findings carry
non-authoritative diagnostic evidence and cannot mutate a candidate. Accepted
corrections use the existing source-aware editorial overlay; only changed IDs
are rechecked. Remaining findings at the configured finite bound produce an
exhaustion/user gate rather than an automatic retry.

Content validation accepts either an exact verified round-zero fluency state or
an exact verified correction terminal. It binds the complete selected fluency
chain into validation authority. Exhaustion, stale candidates and unresolved
findings cannot reach validation.

`CONTENT_VERIFIED` is a content-only terminal state. It does not authorize a
game build, installation or delivery operation.
