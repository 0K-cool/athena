#!/usr/bin/env python3
"""Offline verification of a command evidence log folder."""
import json
import sys

import command_log as cl


def main(argv):
    if len(argv) != 2:
        print("usage: verify_command_log.py <evidence-dir>", file=sys.stderr)
        return 1
    result = cl.verify(argv[1])
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] in ("ok", "ok_with_gaps") else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
