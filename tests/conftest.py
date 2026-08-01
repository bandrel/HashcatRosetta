"""Shared pytest configuration.

Registers fixture modules under tests/fixtures/ as plugins so their
fixtures are available to every test module without needing an explicit
(and lint-unfriendly) import of the fixture name into each test file.
"""

pytest_plugins = ["tests.fixtures.high_byte_rules"]
