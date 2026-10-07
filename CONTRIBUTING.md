# Contributing

Contributions are welcome. Keep changes focused, typed, documented, and covered by local tests. Never add real customer captures, credentials, or private network data to the repository.

1. Create a Python 3.12 virtual environment and install `pip install -e .[dev]`.
2. Run `pytest` and `ruff check .` before opening a pull request.
3. Include a short explanation of behavior changes and any limitations.

Parser changes must treat packet bytes as untrusted, avoid unbounded allocations, and preserve the offline-by-default behavior.
