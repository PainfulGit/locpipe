# Release policy

Package versions follow PEP 440. Contract versions are independent wire
identities. The initial beta package is `0.1.0b1` and freezes contract
`0.1.0-draft.2`.

The additive fluency lifecycle was first assigned package identity `0.2.0b1`.
The public pure translation-terminal reconstruction facade is assigned the
successor package identity `0.2.0b2`. These package-version changes do not alter
the frozen `0.1.0-draft.2` wire identity. Assigning a package identity does not
itself authorize a tag, upload or external publication, and an existing tag or
release asset is never replaced in place.

Patch releases may fix implementation defects without changing accepted wire
bytes. Additive public APIs require tests and documentation. Incompatible
contract changes use a new versioned facade/schema instead of mutating v0.

Each GitHub release contains a wheel, sdist, SHA256 sums, CycloneDX SBOM and the
machine package-gate receipt. PyPI publication is outside the initial beta.
