# Contributing to BVDU-SecQuery

Thanks for helping improve this BVDU Projects project. Contributions should keep the scanner safe, transparent, and usable on Windows, Linux, and macOS.

## Development setup

Use Python 3.10 or newer:

```sh
python -m pip install -e '.[dev]'
python -m pytest
python -m ruff check .
```

If you change dependency versions, run `pip-audit . --progress-spinner off` as well. CI tests Windows, Linux, and macOS on Python 3.10 and 3.12.

## Safety expectations

- Never upload, execute, delete, or remediate a scanned file as a side effect of scanning.
- Keep network lookups limited to documented hash or signature metadata. Never transmit file contents, user paths, or filenames.
- Use bounded reads, decompression limits, timeouts, safe subprocess argument lists, and `shell=False` for external tools.
- Do not follow symlinks/reparse points or extract untrusted archives during inspection.
- Keep quarantine authenticated and recoverable; never log passphrases or place secrets in arguments.
- Treat third-party feeds as untrusted input: validate schemas, hashes, response size, TLS, and freshness.
- Explain uncertainty and engine failures. Never report an incomplete engine scan as clean.
- Do not add paid service requirements, mandatory API keys, or mandatory network dependencies.

## Tests and sample files

Use harmless synthetic fixtures or the official EICAR antivirus test file/string for detection tests. Do not commit live malware, credential-bearing files, or personal data. Tests must not require internet access, administrator rights, or changes to antivirus settings. Mock public feed responses and native antivirus commands.

## Pull requests

Please include the reason for the change, user-visible behavior, affected platforms, test results, and any privacy or security implications. Update `README.md` or `USAGE_GUIDE.md` when commands, providers, limits, or detection behavior change. Keep changes focused and include regression tests for bugs.

For security vulnerabilities, use the private reporting guidance in [SECURITY.md](SECURITY.md) rather than opening a public issue with exploit details.
