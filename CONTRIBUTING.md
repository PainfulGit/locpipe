# Contributing

Changes should be small, deterministic and game-neutral. Open an issue before
adding a capability or changing an artifact contract.

Required checks:

```bash
python -m unittest discover -s tests -p "test_*.py"
python tools/check_public_boundary.py
python tools/check_reproducible.py
```

New adapters must use invented fixtures and the public conformance runner.
Never attach proprietary source data to issues, tests or logs.
