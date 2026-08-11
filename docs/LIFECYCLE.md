# Content lifecycle

```text
adapter corpus
  -> source lock
  -> reconciliation
  -> frozen owned/context scope
  -> translation job and immutable submission
  -> accepted target candidates
  -> optional editorial overlay and bounded rework
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

`CONTENT_VERIFIED` is a content-only terminal state. It does not authorize a
game build, installation or delivery operation.
