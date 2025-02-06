"""
This module is used to load splat configuration from a YAML file.

A config dict can be loaded using `initialize`.

    config = conf.initialize("path/to/splat.yaml")
"""

from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pathlib import Path

# This unused import makes the yaml library faster. don't remove
import pylibyaml  # pyright: ignore
import yaml

import sys

from . import log, options, vram_classes


def _merge_configs(main_config, additional_config):
    # Merge rules are simple
    # For each key in the dictionary
    # - If list then append to list
    # - If a dictionary then repeat merge on sub dictionary entries
    # - Else assume string or number and replace entry

    for curkey in additional_config:
        if curkey not in main_config:
            main_config[curkey] = additional_config[curkey]
        elif type(main_config[curkey]) != type(additional_config[curkey]):
            log.error(f"Type for key {curkey} in configs does not match")
        else:
            # keys exist and match, see if a list to append
            if type(main_config[curkey]) == list:
                main_config[curkey] += additional_config[curkey]
            elif type(main_config[curkey]) == dict:
                # need to merge sub areas
                main_config[curkey] = _merge_configs(
                    main_config[curkey], additional_config[curkey]
                )
            else:
                # not a list or dictionary, must be a number or string, overwrite
                main_config[curkey] = additional_config[curkey]

    return main_config


def _resolve_path(base: Path, rel: Path, include_paths: List[Path]) -> Path:
    if (base / rel).exists():
        return base / rel

    for path in include_paths:
        candidate = path / rel
        if candidate.exists():
            return candidate
    log.error(f'"{rel}" not found')


def _load_config(config_path: Path, include_path: List[Path]) -> Dict[str, Any]:
    base_path = Path(config_path).parent
    with open(config_path) as f:
        config = yaml.load(f.read(), Loader=yaml.SafeLoader)
    if "parent" in config:
        parent_path = _resolve_path(base_path, Path(config["parent"]), include_path)
        parent = _load_config(parent_path, include_path)
        config = _merge_configs(parent, config)
        del config["parent"]

    return config


def initialize(
    config_path: List[str],
    include_path: List[Path] = [],
    modes: Optional[List[str]] = None,
    verbose: bool = False,
    disassemble_all: bool = False,
) -> Dict[str, Any]:
    """
    Returns a `dict` with resolved splat config.

    Multiple configuration files can be passed in ``config_path`` with each
    subsequent file merged into the previous. `parent` keys are resolved
    prior to merging multiple files.

    `include_path` can include any additional paths which should be searched for relative parent config files. Paths are
    relative to the file being evaluated (i.e. a child config file).

    `modes` specifies which modes are active (all, code, img, gfx, vtx, etc.). The default is all.

    `verbose` may be used to determine whether or not to display additional output.

    `disassemble_all` determines whether functions which are already compiled will be disassembled.

    After being merged, static validation is done on the configuration.

    The returned `dict` represents the merged and validated YAML.
    """

    config: Dict[str, Any] = {}
    for entry in config_path:
        additional_config = _load_config(Path(entry), include_path)
        config = _merge_configs(config, additional_config)

    vram_classes.initialize(config.get("vram_classes"))

    options.initialize(config, config_path, modes, verbose, disassemble_all)

    return config
