#!/usr/bin/env python3
"""Strict wrapper for the SmallWood HX512 trace screen."""

from trace_screen import check_screen


if __name__ == "__main__":
    check_screen()
    print("PASS smallwood-hx512-trace-screen production=false proof_bytes=null")

