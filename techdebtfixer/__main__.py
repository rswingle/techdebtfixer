"""Allow `python -m techdebtfixer`."""

import sys

from techdebtfixer.cli import main

if __name__ == "__main__":
    sys.exit(main())
