#!/usr/bin/env python3

import argparse

import splat


def splat_main():
    parser = argparse.ArgumentParser(
        description="A binary splitting tool to assist with decompilation and modding projects",
        prog="splat",
    )

    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {splat.__version__}"
    )

    subparsers = parser.add_subparsers(
        description="action", help="The CLI utility to run", required=True
    )

    splat.scripts.split.add_subparser(subparsers)
    splat.scripts.create_config.add_subparser(subparsers)
    splat.scripts.capy.add_subparser(subparsers)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    splat_main()
