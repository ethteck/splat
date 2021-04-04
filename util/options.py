from typing import Dict
from pathlib import Path
import sys

opts = {}

def initialize(config: Dict, config_path: str, base_dir=None, target_path=None):
    global opts
    opts = dict(config.get("options", {}))

    if base_dir:
        opts["base_dir"] = Path(base_dir)
    else:
        if not "base_dir" in opts:
            print("Error: Base output dir not specified as a command line arg or via the config yaml (base_dir)")
            sys.exit(2)

        opts["base_dir"] = Path(config_path).parent / opts["base_dir"]

    if not target_path:
        if "target_path" not in opts:
            print("Error: Target binary path not specified as a command line arg or via the config yaml (target_path)")
            sys.exit(2)

def set(opt, val):
    opts[opt] = val
    
def get(opt, default=None):
    return opts.get(opt, default)

def mode_active(mode):
    return mode in opts["modes"] or "all" in opts["modes"]

def get_base_path() -> Path:
    return Path(opts["base_dir"])

def get_asset_dir() -> str:
    return opts.get("asset_dir", "assets")

def get_asset_path() -> Path:
    return get_base_path() / get_asset_dir()

def get_target_path() -> Path:
    return get_base_path() / opts["target_path"]

def get_src_path() -> Path:
    return get_base_path() / opts.get("src_path", "src")

def get_asm_path() -> Path:
    return get_base_path() / opts.get("asm_path", "asm")

def get_cache_path():
    return get_base_path() / opts.get("cache_path", ".splat_cache")

def get_undefined_funcs_auto_path():
    return get_base_path() / opts.get("undefined_funcs_auto_path", "undefined_funcs_auto.txt")

def get_undefined_syms_auto_path():
    return get_base_path() / opts.get("undefined_syms_auto_path", "undefined_syms_auto.txt")

def get_symbol_addrs_path():
    return get_base_path() / opts.get("symbol_addrs_path", "symbol_addrs.txt")

def get_ld_script_path():
    return get_base_path() / opts.get("ld_script_path", f"{opts.get('basename')}.ld")
