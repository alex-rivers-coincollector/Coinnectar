#!/usr/bin/env python3
"""
Coinnectar setup script.

Builds the C extension speedups if a compatible C compiler is present;
otherwise falls back seamlessly to pure Python execution.
"""

import os
import sys
from setuptools import Extension, find_packages, setup
from setuptools.command.build_ext import build_ext

# Environment flag to force pure Python build (e.g. for PyPy or constrained environments)
NO_C_EXTENSIONS = os.environ.get("COINNECTAR_NO_C_EXTENSIONS", "0") == "1"


class OptionalBuildExt(build_ext):
    """Custom build_ext that warns and continues if C extensions fail to compile."""

    def run(self):
        try:
            super().run()
        except Exception as exc:
            print("\n" + "=" * 70, file=sys.stderr)
            print("WARNING: Failed to compile Coinnectar C speedup extension:", file=sys.stderr)
            print(f"  {exc}", file=sys.stderr)
            print("Continuing with pure Python installation.", file=sys.stderr)
            print("=" * 70 + "\n", file=sys.stderr)

    def build_extension(self, ext):
        try:
            super().build_extension(ext)
        except Exception as exc:
            print("\n" + "=" * 70, file=sys.stderr)
            print(f"WARNING: Building {ext.name} failed: {exc}", file=sys.stderr)
            print("Coinnectar will operate using pure Python fallbacks.", file=sys.stderr)
            print("=" * 70 + "\n", file=sys.stderr)


ext_modules = []
if not NO_C_EXTENSIONS:
    ext_modules.append(
        Extension(
            name="coinnectar._native",
            sources=[
                "c_src/serialize.c",
                "c_src/crypto_helpers.c",
            ],
            include_dirs=["c_src"],
            extra_compile_args=["-O3"] if sys.platform != "win32" else ["/O2"],
            optional=True,
        )
    )

setup(
    ext_modules=ext_modules,
    cmdclass={"build_ext": OptionalBuildExt},
)
