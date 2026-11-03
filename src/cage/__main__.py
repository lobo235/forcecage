"""``python -m cage`` -- the forcecage entry point."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
