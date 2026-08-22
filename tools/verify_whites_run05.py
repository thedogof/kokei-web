#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "public/whites-run05.html"
BUILD = ROOT / "public/whites-run05-build.json"
CONTRACT = ROOT / "public/whites-run05-assets/README.md"
EXPECTED_VERSION = "KQ-WHITES-RUN05-v0.4"
EXPECTED_SOURCE = "thedogof/kokei-web:main/public/whites-run05.html"
EXPECTED_GEOMETRY = (2664, 1924)
ASSETS = {
    "public/whites-run05-assets/scene1.png": (
        4_528_886,
        "08e2ae12ac5942704f7aa970cc64c7ee23cc7c7cda0d0355e06df75dfc7e1d6e",
    ),
    "public/whites-run05-assets/scene2.png": (
        2_763_120,
        "679bc0bf3abd788ac008ac248ce3ff7832644c344485a2b52f80008bc3f53ace",
    ),
    "public/whites-run05-assets/scene3.png": (
        2_350_774,
        "a40037373bfe222add107c640043c501ff981178a4585c4508455404c3102c14",
    ),
}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def png_geometry(data: bytes) -> tuple[int, int]:
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        fail("asset is not a valid PNG signature")
    if data[12:16] != b"IHDR":
        fail("PNG IHDR is not in the canonical position")
    return struct.unpack(">II", data[16:24])


def last_harness_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "log", "-1", "--format=%H", "--", "public/whites-run05.html"],
            cwd=ROOT,
            text=True,
        ).strip()
    except Exception as exc:
        fail(f"cannot resolve harness git commit: {exc}")


def main() -> None:
    for required in (HARNESS, BUILD, CONTRACT):
        if not required.is_file():
            fail(f"missing required file: {required.relative_to(ROOT)}")

    harness_text = HARNESS.read_text(encoding="utf-8")
    build_text = BUILD.read_text(encoding="utf-8")
    contract_text = CONTRACT.read_text(encoding="utf-8")

    # The blind mapping must not leak into any client-facing RUN05 metadata.
    client_text = "\n".join((harness_text, build_text, contract_text))
    for forbidden in ("S10", "S20"):
        if forbidden in client_text:
            fail(f"private mapping token leaked into client-facing RUN05 files: {forbidden}")

    try:
        build = json.loads(build_text)
    except json.JSONDecodeError as exc:
        fail(f"invalid build metadata JSON: {exc}")

    if build.get("harnessVersion") != EXPECTED_VERSION:
        fail(f"build harnessVersion mismatch: {build.get('harnessVersion')!r}")
    if build.get("sourcePointer") != EXPECTED_SOURCE:
        fail(f"build sourcePointer mismatch: {build.get('sourcePointer')!r}")
    harness_commit = build.get("harnessCommit", "")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", harness_commit):
        fail("build harnessCommit is missing or malformed")
    actual_harness_commit = last_harness_commit()
    if harness_commit.lower() != actual_harness_commit.lower():
        fail(
            "build harnessCommit does not match the commit that last changed the harness: "
            f"{harness_commit} != {actual_harness_commit}"
        )

    required_harness_tokens = (
        f"const VERSION='{EXPECTED_VERSION}'",
        "function sameOriginURL(",
        "build pointer redirected off-origin",
        "redirected off-origin",
        "crypto.subtle.digest('SHA-256'",
        "HTTPS secure context required",
    )
    for token in required_harness_tokens:
        if token not in harness_text:
            fail(f"harness is missing integrity token: {token}")

    for rel_path, (expected_bytes, expected_sha) in ASSETS.items():
        path = ROOT / rel_path
        if not path.is_file():
            fail(f"missing canonical asset: {rel_path}")
        data = path.read_bytes()
        if len(data) != expected_bytes:
            fail(f"{rel_path} byte length {len(data)} != {expected_bytes}")
        actual_sha = hashlib.sha256(data).hexdigest()
        if actual_sha != expected_sha:
            fail(f"{rel_path} SHA-256 {actual_sha} != {expected_sha}")
        geometry = png_geometry(data)
        if geometry != EXPECTED_GEOMETRY:
            fail(f"{rel_path} geometry {geometry} != {EXPECTED_GEOMETRY}")
        if str(expected_bytes) not in harness_text or expected_sha not in harness_text:
            fail(f"harness manifest does not contain canonical identity for {rel_path}")
        print(f"PASS asset: {rel_path} · {expected_bytes} bytes · {expected_sha} · {geometry[0]}x{geometry[1]}")

    print(f"PASS harness: {EXPECTED_VERSION} · commit {harness_commit}")
    print("PASS hidden-key check: S10/S20 absent from client-facing RUN05 files")
    print("PASS Whites RUN05 repository integrity gate")


if __name__ == "__main__":
    main()
