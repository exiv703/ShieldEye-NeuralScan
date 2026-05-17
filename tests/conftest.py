# Why: samples/ contains intentionally vulnerable fixtures, not test suite — exclude from pytest collection
collect_ignore_glob = ["samples/*"]
