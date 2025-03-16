"""
This module is used to load splat configuration from a YAML file.

A config dict can be loaded using `load`.

    config = conf.load("path/to/splat.yaml")
"""

from typing import Any, Dict, List, Optional
from pathlib import Path

# This unused import makes the yaml library faster. don't remove
import pylibyaml  # pyright: ignore
import yaml

from . import log, options, vram_classes


def _merge_configs(main_config, additional_config, additional_config_path):
    # Merge rules are simple
    # For each key in the dictionary
    # - If list then append to list
    # - If a dictionary then repeat merge on sub dictionary entries
    # - Else assume string or number and replace entry

    for curkey in additional_config:
        if curkey not in main_config:
            main_config[curkey] = additional_config[curkey]
        elif type(main_config[curkey]) != type(additional_config[curkey]):
            raise TypeError(
                f"Could not merge {str(additional_config_path)}: type for key '{curkey}' in configs does not match"
            )
        else:
            # keys exist and match, see if a list to append
            if type(main_config[curkey]) == list:
                main_config[curkey] += additional_config[curkey]
            elif type(main_config[curkey]) == dict:
                # need to merge sub areas
                main_config[curkey] = _merge_configs(
                    main_config[curkey],
                    additional_config[curkey],
                    additional_config_path,
                )
            else:
                # not a list or dictionary, must be a number or string, overwrite
                main_config[curkey] = additional_config[curkey]

    return main_config


def load(
    config_path: List[Path],
    modes: Optional[List[str]] = None,
    verbose: bool = False,
    disassemble_all: bool = False,
    make_full_disasm_for_code=False,
) -> Dict[str, Any]:
    """
    Returns a `dict` with resolved splat config.

    Multiple configuration files can be passed in ``config_path`` with each subsequent file merged into the previous.

    `modes` specifies which modes are active (all, code, img, gfx, vtx, etc.). The default is all.

    `verbose` may be used to determine whether or not to display additional output.

    `disassemble_all` determines whether functions which are already compiled will be disassembled. This is OR-ed with
    the `disassemble_all` key in a config file, if present.

    After all files are merged, static validation is done on the configuration.

    The returned `dict` represents the merged and validated YAML config.

    As a side effect, the global `splat.util.options.opts` is set.

    Config with invalid options may raise an error.
    """

    config: Dict[str, Any] = {}
    for entry in config_path:
        with entry.open() as f:
            additional_config = yaml.load(f.read(), Loader=yaml.SafeLoader)
        config = _merge_configs(config, additional_config, entry)

    vram_classes.initialize(config.get("vram_classes"))

    options.initialize(
        config,
        config_path,
        modes,
        verbose,
        disassemble_all,
        make_full_disasm_for_code,
    )

    return config
