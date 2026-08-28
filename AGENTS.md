# Agent guide

Before changing code:

1. Read `README.md`, `docs/ARCHITECTURE.md`, root `SECURITY.md`,
   `docs/SECURITY_MODEL.md` and the relevant versioned facade.
2. Run `python -m unittest discover -s tests -p "test_*.py"`.
3. Run `locpipe-demo` from an installed wheel for package-facing changes.

Invariants:

- game-specific rules belong in adapters, never in generic core;
- adapters write only to declared staging and cannot publish authority;
- raw provider/editor outputs and receipts are immutable;
- unknown schema, identity, relation, path or digest fails closed;
- content findings use bounded rework; integrity drift is not content rework;
- never commit game text, translations, assets, credentials or local paths;
- do not change frozen v0 wire bytes; incompatible changes require a new
  versioned surface.

Keep public APIs in versioned facades. Underscore modules are implementation
details. Add invented fixtures for every new generic behavior.
