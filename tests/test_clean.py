#!/usr/bin/env python3
"""
TEST FILE — clean code that should produce zero findings.
Used to verify no false positives on normal code.
"""

import os
import json
import hashlib
from pathlib import Path


def read_config(path: str) -> dict:
    """Read a JSON config file."""
    with open(path, "r") as f:
        return json.load(f)


def hash_file(path: str) -> str:
    """Compute SHA256 hash of a file."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            sha.update(chunk)
    return sha.hexdigest()


def list_files(directory: str) -> list:
    """List all files in a directory recursively."""
    files = []
    for root, dirs, fnames in os.walk(directory):
        for fname in fnames:
            files.append(os.path.join(root, fname))
    return files


def main():
    config = read_config("config.json")
    print(f"Processing {len(config.get('files', []))} files")

    for file_path in config.get("files", []):
        h = hash_file(file_path)
        print(f"  {file_path}: {h}")


if __name__ == "__main__":
    main()
