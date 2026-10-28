#!/usr/bin/env python3
"""Recording moved to the optional zhulong-record-bundle skill.

Invoke that skill explicitly with --zhulong-root pointing to this core. This
compatibility entry never reads bundles, controls the desktop, or delegates.
Historical materials remain supported by validate_recording_evidence.py.
"""
import sys


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    print(__doc__, file=sys.stdout if arguments in (["--help"], ["-h"]) else sys.stderr)
    return 0 if arguments in (["--help"], ["-h"]) else 2


if __name__ == "__main__":
    raise SystemExit(main())
