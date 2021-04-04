from pathlib import Path
import sys

opts = {}

def initialize(config, config_path, base_dir=None, target_path=None):
    global opts
    opts = config.get("options")
    
    if not base_dir:
        if not "base_dir" in opts:
            print("Error: Base output dir not specified as a command line arg or via the config yaml (base_dir)")
            sys.exit(2)
        else:
            opts.set("base_dir", Path(config_path).parent / base_dir)

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

def get_basedir() -> Path:
    return Path(opts.get("base_dir", ""))

def get_asset_dir() -> str:
    return opts.get("asset_dir", "assets")

def get_asset_path() -> Path:
    return get_basedir() / get_asset_dir()

def get_target_path() -> Path:
    return get_basedir() / opts.get("target_path")

def get_cache_path():
    return get_basedir() / opts.get("cache_path", ".splat_cache")

def get_undefined_funcs_auto_path():
    return get_basedir() / opts.get("undefined_funcs_auto_path", "undefined_funcs_auto.txt")

def get_undefined_syms_auto_path():
    return get_basedir() / opts.get("undefined_syms_auto_path", "undefined_syms_auto.txt")

def get_symbol_addrs_path():
    return get_basedir() / opts.get("symbol_addrs_path", "symbol_addrs.txt")

def get_ld_script_path():
    return get_basedir() / opts.get("ld_script_path", f"{opts.get('basename')}.ld")