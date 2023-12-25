#! /usr/bin/env python3

import src.splat as splat

if __name__ == "__main__":
    args = splat.scripts.split.parser.parse_args()
    splat.scripts.split.main(
        args.config,
        args.modes,
        args.verbose,
        args.use_cache,
        args.skip_version_check,
        args.stdout_only,
        args.disassemble_all,
    )
