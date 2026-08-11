# Troubleshooting

- `BINDING_MISMATCH`: verify exact adapter/module/provider ID, version and
  digest; do not reuse evidence from another job.
- `HASH_MISMATCH`: restore the declared immutable artifact or create a new job;
  never edit a receipt to match changed bytes.
- `PATH_ESCAPE`: remove links/reparse points and use a dedicated relative
  workspace.
- `SOURCE_DRIFT`: extract the new source, reconcile it and revalidate stale
  targets before continuing.
- `REWORK_EXHAUSTED`: request an explicit user decision; do not create an
  unbounded retry loop.
- `WRITER_LOCKED`: another writer owns the namespace. Automatic stealing is not
  supported by the beta.
