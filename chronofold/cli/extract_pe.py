#!/usr/bin/env python3
import argparse
import hashlib
import json
import pathlib
import platform
import sys
import lief
import pefile

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("-o", "--output", required=True)
    args = ap.parse_args()
    p = pathlib.Path(args.exe).resolve()
    pe = pefile.PE(str(p), fast_load=False)
    binary = lief.parse(str(p))
    result = {
        "schema": "cf-ir/pe-v0.1",
        "artifact": {
            "path": str(p),
            "sha256": sha256(p),
            "size_bytes": p.stat().st_size,
            "format": str(binary.format),
            "architecture": str(binary.header.machine),
            "entrypoint": hex(binary.entrypoint),
        },
        "pe": {
            "machine": hex(pe.FILE_HEADER.Machine),
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "characteristics": hex(pe.FILE_HEADER.Characteristics),
            "sections": [
                {
                    "name": s.Name.rstrip(b"\0").decode("ascii", "replace"),
                    "virtual_size": s.Misc_VirtualSize,
                    "raw_size": s.SizeOfRawData,
                    "entropy": round(s.get_entropy(), 6),
                }
                for s in pe.sections
            ],
            "imports": [
                {
                    "dll": e.dll.decode("utf-8", "replace") if e.dll else "",
                    "symbols": [
                        (i.name or b"").decode("utf-8", "replace")
                        if i.name else "ordinal:" + str(i.ordinal)
                        for i in e.imports
                    ],
                }
                for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
            ],
        },
        "provenance": {
            "python": platform.python_version(),
            "lief": lief.__version__,
            "pefile": getattr(pefile, "__version__", "unknown"),
            "platform": platform.platform(),
            "argv": sys.argv,
        },
    }
    out = pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
