"""Accept only Tauri's single UNK -> NSS bundle marker patch."""
import hashlib
import json
import sys
from pathlib import Path

MARKER = b'__TAURI_BUNDLE_TYPE_VAR_'


def verify(compiled: bytes, installed: bytes, extracted: bytes) -> dict:
    if installed != extracted:
        raise ValueError('Installed and extracted executables differ')
    if compiled.count(MARKER) != 1 or installed.count(MARKER) != 1:
        raise ValueError('Expected exactly one Tauri bundle marker')
    offset = compiled.index(MARKER) + len(MARKER)
    if compiled[offset:offset + 3] != b'UNK':
        raise ValueError('Unexpected compiled bundle type')
    expected = compiled[:offset] + b'NSS' + compiled[offset + 3:]
    if installed != expected:
        raise ValueError('Executable differs beyond the permitted UNK -> NSS patch')
    return {
        'bundleMarkerOffset': offset,
        'allowedPatch': 'UNK -> NSS',
        'expectedInstalledSha256': hashlib.sha256(expected).hexdigest(),
        'installedSha256': hashlib.sha256(installed).hexdigest(),
        'verified': True,
    }


if __name__ == '__main__':
    result = verify(*(Path(p).read_bytes() for p in sys.argv[1:4]))
    print(json.dumps(result, indent=2))
