# Release policy

Package versions follow PEP 440. Contract versions are independent wire
identities. The initial beta package is `0.1.0b1` and freezes contract
`0.1.0-draft.2`.

The additive fluency lifecycle was first assigned package identity `0.2.0b1`.
The public pure translation-terminal reconstruction facade is assigned the
successor package identity `0.2.0b2`. The additive parsed-source authority
rebinding facade is assigned package identity `0.2.0b3`, with future annotated
tag contract `v0.2.0-beta.3`. It reuses exact immutable parsed segment and
relation tuples without a filesystem reread or canonical reparse while
constructing fresh config-bound source-lock and reconciliation authority.
These package-version changes do not alter the frozen `0.1.0-draft.2` wire
identity or exact `rfc8785==0.1.4` runtime dependency. Assigning a package
identity does not itself authorize a tag, upload or external publication, and
an existing tag or release asset, including beta.1 and beta.2, is never
replaced in place.

Patch releases may fix implementation defects without changing accepted wire
bytes. Additive public APIs require tests and documentation. Incompatible
contract changes use a new versioned facade/schema instead of mutating v0.

Each GitHub release contains a wheel, sdist, SHA256 sums, CycloneDX SBOM and the
machine package-gate receipt. PyPI publication is outside the initial beta.
