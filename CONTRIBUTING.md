# Contributing to Nmap Wrapper

Contributions are welcome for validation, command construction, UI, documentation, portability, and test coverage.

## Rules

- Use only documentation-safe example targets in tests and issue reports.
- Never commit credentials, private infrastructure, scan results from third parties, or sensitive logs.
- Keep command-generation changes explicit and reviewable.
- Test on the operating systems affected by your change.

## Validation

Run:

```bash
python -m unittest discover -s tests -v
python -m py_compile nmap_wrapper.py nmap_wrapper_gui.py
```

Use the pull-request template and explain any privilege or Nmap-version assumptions.
