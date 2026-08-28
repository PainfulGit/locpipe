# Security model

The core protects deterministic evidence against accidental or conflicting
writes through exact bindings, canonical hashes, path containment, leases,
fencing epochs, preimages, journals and rollback.

The following remain outside the beta trust boundary:

- hostile or untrusted adapter code;
- network provider dispatch;
- game executables, build tools and installers;
- secret storage;
- automatic lock stealing.

Run adapters in a dedicated process or sandbox when their code is not trusted.
Never place proprietary source payload in logs, issue reports or public test
fixtures.

The fluency packet builder accepts only a trusted project-produced target-side
projection with a closed field/origin shape. Generic core does not infer payload
language. Source artifacts and constraints are absent from the reviewer packet,
and reviewer findings have no replacement authority. Any candidate mutation is
recomputed through the existing receipt-bound editorial overlay before a
corrected-ID-only target recheck. Complete verified fluency authority is then
hash-bound into the existing content-validation job; no parallel publication or
recovery system is introduced.
