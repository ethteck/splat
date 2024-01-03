#! /usr/bin/env python3

from pathlib import Path

import src.splat as splat

if __name__ == "__main__":
    args = splat.scripts.create_config.parser.parse_args()
    splat.scripts.create_config.main(Path(args.file))
