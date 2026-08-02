#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import pathlib
import sys

EXPECTED_SHA256 = "f160bf701d0e1291d50f958ac55941cc2fb63a4e9807ef9c847582affd9e3899"
LOCAL = pathlib.Path("src/test/resources/snapshot-v1-vector.json")


def canonical_file_bytes(path: pathlib.Path) -> bytes:
    value = path.read_bytes()
    return value[:-1] if value.endswith(b"\n") else value


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify-consumer-vector.py <consumer-vector>")
    local = canonical_file_bytes(LOCAL)
    consumer = canonical_file_bytes(pathlib.Path(sys.argv[1]))
    if local != consumer:
        raise SystemExit("registry and pinned consumer vectors differ")
    if len(local) != 333:
        raise SystemExit(f"unexpected vector byte length: {len(local)}")
    digest = hashlib.sha256(local).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"unexpected vector digest: {digest}")
    print(f"consumer vector compatible: {len(local)} bytes, sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
