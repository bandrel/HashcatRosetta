"""Unit tests for scripts/sweep_opcodes.py — pure-logic pieces only.

The sweep script lives in scripts/ (not in the package), so we import it via
importlib to keep it test-discoverable without polluting the public API.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest  # noqa: F401

_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "sweep_opcodes.py"
_spec = importlib.util.spec_from_file_location("sweep_opcodes", _SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
sweep_opcodes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sweep_opcodes)


class TestArgGridConstants:
    def test_position_args_are_hashcat_position_chars(self):
        # Hashcat encodes positions 0-9 as '0'-'9' and 10-35 as 'A'-'Z'.
        for arg in sweep_opcodes.POSITION_ARGS:
            assert len(arg) == 1
            assert arg in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def test_char_args_are_single_chars(self):
        for arg in sweep_opcodes.CHAR_ARGS:
            assert len(arg) == 1

    def test_two_arg_grid_is_3x3_pairs(self):
        assert len(sweep_opcodes.TWO_ARG_GRID) == 9
        for pair in sweep_opcodes.TWO_ARG_GRID:
            assert len(pair) == 2
            assert all(len(c) == 1 for c in pair)

    def test_three_arg_grid_is_triples(self):
        assert len(sweep_opcodes.THREE_ARG_GRID) > 0
        for triple in sweep_opcodes.THREE_ARG_GRID:
            assert len(triple) == 3

    def test_known_latent_is_dict_str_str(self):
        assert isinstance(sweep_opcodes.KNOWN_LATENT, dict)
        for k, v in sweep_opcodes.KNOWN_LATENT.items():
            assert isinstance(k, str) and len(k) == 1
            assert isinstance(v, str) and len(v) > 0
