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
