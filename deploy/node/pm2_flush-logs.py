#!/usr/bin/env python3
import os
import subprocess
import sys


def run(cmd):
    return subprocess.run(cmd, check=True)


def main():
    try:
        run(["pm2", "flush"])
    except Exception as exc:
        print(f"pm2 flush failed: {exc}", file=sys.stderr)
        return 1

    log_paths = [
        "/var/log/caddy/access.log",
        "/var/log/caddy/error.log",
    ]

    for path in log_paths:
        if not os.path.exists(path):
            print(f"skip (missing): {path}")
            continue
        try:
            run(["sudo", "truncate", "-s", "0", path])
            print(f"cleared: {path}")
        except Exception as exc:
            print(f"failed to clear {path}: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
