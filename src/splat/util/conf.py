from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pathlib import Path

# This unused import makes the yaml library faster. don't remove
import pylibyaml  # pyright: ignore
import yaml

import sys

from . import log, options, vram_classes


def merge_configs(main_config, additional_config):
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
                main_config[curkey] = merge_configs(
                    main_config[curkey], additional_config[curkey]
                )
            else:
                # not a list or dictionary, must be a number or string, overwrite
                main_config[curkey] = additional_config[curkey]

    return main_config


def resolve_path(base: Path, rel: Path, include_paths: List[Path]) -> Path:
    if (base / rel).exists():
        return base / rel

    for path in include_paths:
        candidate = path / rel
        if candidate.exists():
            return candidate
    log.error(f'"{rel}" not found')
    return None


def load_config(config_path: Path, include_path: List[Path]) -> Dict[str, Any]:
    base_path = Path(config_path).parent
    with open(config_path) as f:
        config = yaml.load(f.read(), Loader=yaml.SafeLoader)
    if "parent" in config:
        parent_path = resolve_path(base_path, Path(config["parent"]), include_path)
        parent = load_config(parent_path, include_path)
        config = merge_configs(parent, config)
        del config["parent"]

    return config


def initialize(
    config_path: List[str],
    include_path: List[Path],
    modes: Optional[List[str]],
    verbose: bool,
    disassemble_all: bool = False,
) -> Dict[str, Any]:
    config: Dict[str, Any] = {}
    for entry in config_path:
        additional_config = load_config(Path(entry), include_path)
        config = merge_configs(config, additional_config)

    vram_classes.initialize(config.get("vram_classes"))

    options.initialize(config, config_path, modes, verbose, disassemble_all)

    return config
