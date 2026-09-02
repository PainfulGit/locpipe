# Changelog

## 0.2.0b4

- Add the public `prepare_accepted_source_authority_v0` and
  `rebind_prepared_source_authority_v0` facades. The process-local authority
  retains accepted canonical bytes, one prepared row layer and immutable
  identity-sharing indexes.
- Add public `build_translation_job_prepared_v0` and
  `build_content_validation_job_prepared_v0` entrypoints that preserve exact
  canonical results while making warm work proportional to the selected scope
  and its incident dependencies.
- Share scope acceptance semantics between canonical and prepared paths. The
  trusted-process binder rejects ordinary unsupported construction, copying,
  pickling, cross-process use and top-level substitution; deliberate same-process
  mutation through private mechanisms is outside the contract.
- Preserve the frozen `0.1.0-draft.2` wire contract and exact
  `rfc8785==0.1.4` runtime dependency.

The future annotated-tag contract is `v0.2.0-beta.4`. Assigning this package
identity does not itself authorize a tag, release asset upload or external
publication. Existing beta.1, beta.2 and beta.3 tags and release assets remain
immutable and are never replaced in place.

## 0.2.0b3

- Add the public `rebind_source_authority_v0` facade for rebinding an already
  parsed source corpus to an exact configuration snapshot without filesystem
  reads or canonical segment/relation reparsing. The facade reuses the exact
  immutable parsed tuples, constructs fresh source-lock and reconciliation
  authority, rejects stale or foreign reconciliation, and does not copy prior
  reconciliation history.
- Preserve the frozen `0.1.0-draft.2` wire contract and exact
  `rfc8785==0.1.4` runtime dependency.

The future annotated-tag contract is `v0.2.0-beta.3`. Assigning this package
identity does not itself authorize a tag, release asset upload or external
publication. Existing beta.1 and beta.2 tags and release assets remain
immutable and are never replaced in place.

## 0.2.0b2

- Expose pure `translation_terminal_artifacts_v0` reconstruction through the
  public translation facade so exact accepted translation authority can be
  recomputed without filesystem handling or private imports.
- Preserve the frozen `0.1.0-draft.2` wire contract and existing translation
  handler acceptance behavior.

Assigning this package identity does not itself authorize a tag, release asset
upload or external publication.

## 0.2.0b1

- Additive `locpipe.fluency.v0` target-only review contracts with exact coverage,
  immutable findings, bounded source-aware correction, corrected-ID recheck and
  exact fluency authority binding into existing content validation.
- Packaged invented lifecycle evidence for no-findings and one-correction paths;
  both reuse existing validation publication and reach `CONTENT_VERIFIED`.

## 0.1.0b1

- Frozen deterministic contracts v0 beta baseline.
- Namespaced context, configuration and transactional publication.
- Read-only adapter SDK and invented conformance fixtures.
- Source reconciliation, frozen scopes, immutable provider acceptance,
  editorial overlays, bounded rework and deterministic content validation.
- Synthetic lifecycle to `CONTENT_VERIFIED`.
- Accept equivalent Windows long and 8.3 artifact-root identities while retaining
  reparse and containment checks.
