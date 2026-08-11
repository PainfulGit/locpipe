# Architecture

The package is organized as versioned, import-only facades:

- `locpipe.contracts.v0`: canonical bytes, identities, schemas and operation
  boundaries;
- `locpipe.kernel.v0`: configuration, contexts, leases and transactional
  publication;
- `locpipe.adapters.v0`: trusted read-only `probe -> extract -> map` adapters;
- `locpipe.content.v0`: source locks, reconciliation and frozen scope;
- `locpipe.translation.v0`: immutable provider jobs and acceptance;
- `locpipe.editorial.v0`: receipt-bound corrections and bounded rework;
- `locpipe.validation.v0`: deterministic validation and `CONTENT_VERIFIED`.

Handlers see declared inputs and isolated staging. Core validates hashes and
publishes through leases and CAS transactions. Adapters and provider modules do
not create authoritative receipts.

The package is game-, language- and provider-neutral. A project supplies pinned
adapters/modules, configuration, source data and policy outside the core.
