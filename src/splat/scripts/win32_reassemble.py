"""Reassemble a splat-split win32 PE back into a single PE/EXE/DLL.

Pipeline:

  1. Run `as` on every .s under asm_path / data_path → .o files placed
     at the build_path layout the splat-generated linker script
     expects (build/asm/<rel>.s.o).
  2. Wrap any .bin assets into ELF objects via `objcopy -I binary -O
     elf32-i386|elf64-x86-64` so they can be linked in.
  3. Invoke `ld -T <splat.ld>` from the base_path to produce an ELF
     image whose section layout matches the original PE.
  4. Run `objcopy -O pei-i386|pei-x86-64` to convert the ELF to a PE.

Output defaults to `<target>.reasm` next to the original target
binary so an accidental run doesn't clobber the source.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

import yaml

from ..util import log


def _which(cmd: str) -> str:
    found = shutil.which(cmd)
    if not found:
        log.error(
            f"win32_reassemble: required tool '{cmd}' not on PATH — "
            "install binutils (provides as / ld / objcopy)"
        )
    return found


def _read_yaml(yaml_path: Path) -> dict:
    return yaml.safe_load(yaml_path.read_text(encoding="utf-8"))


def _detect_bitness(yaml_path: Path, conf: dict) -> bool:
    """Return True if the source PE is PE32+ (x86_64). Inspect the
    `target_path` binary's optional-header magic."""
    target = conf["options"].get("target_path")
    if not target:
        log.error("win32_reassemble: YAML missing options.target_path")
    opts = conf["options"]
    base_path = (yaml_path.parent / opts.get("base_path", ".")).resolve()
    target_path = (base_path / target).resolve()
    if not target_path.exists():
        log.error(f"win32_reassemble: target binary not found at {target_path}")
    data = target_path.read_bytes()
    if len(data) < 0x100 or data[:2] != b"MZ":
        log.error(f"win32_reassemble: {target_path} is not a PE")
    pe_off = int.from_bytes(data[0x3C:0x40], "little")
    magic = int.from_bytes(data[pe_off + 0x18 : pe_off + 0x1A], "little")
    return magic == 0x20B


def _run(cmd: List[str], verbose: bool, cwd: Optional[Path] = None) -> None:
    if verbose:
        prefix = f"(cd {cwd}) " if cwd else ""
        print(f"$ {prefix}" + " ".join(str(c) for c in cmd))
    r = subprocess.run(cmd, capture_output=True, cwd=str(cwd) if cwd else None)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode(errors="replace"))
        log.error(f"win32_reassemble: command failed: {cmd[0]}")


def _collect_sources(
    asm_path: Path, data_path: Path, asset_path: Path
) -> "tuple[List[Path], List[Path]]":
    """Return (.s sources, .bin assets) under the splat-configured
    source directories."""
    s_paths: List[Path] = []
    seen = set()
    for root in (asm_path, data_path):
        if not root.exists():
            continue
        for p in sorted(root.rglob("*.s")):
            if p in seen:
                continue
            seen.add(p)
            s_paths.append(p)
    bin_paths: List[Path] = []
    if asset_path.exists():
        bin_paths = sorted(asset_path.rglob("*.bin"))
    return s_paths, bin_paths


def reassemble(yaml_path: Path, out_path: Path, verbose: bool = False) -> Path:
    """Drive the full assemble + link + PE-convert pipeline for a
    splat-generated win32 config. Returns the path to the produced PE."""
    conf = _read_yaml(yaml_path)
    opts = conf["options"]
    base_path = (yaml_path.parent / opts.get("base_path", ".")).resolve()
    asm_path = (base_path / opts.get("asm_path", "asm")).resolve()
    data_path = (base_path / opts.get("data_path", "data")).resolve()
    asset_path = (base_path / opts.get("asset_path", "assets")).resolve()
    build_path = (base_path / opts.get("build_path", "build")).resolve()
    ld_path = base_path / opts.get("ld_script_path", "")
    if not ld_path.exists():
        log.error(
            f"win32_reassemble: linker script not found at {ld_path} — "
            "run `python -m splat split <yaml>` first"
        )

    is_pe32_plus = _detect_bitness(yaml_path, conf)
    mode_flag = "--64" if is_pe32_plus else "--32"
    ld_emulation = "elf_x86_64" if is_pe32_plus else "elf_i386"
    bin_obj_fmt = "elf64-x86-64" if is_pe32_plus else "elf32-i386"
    bin_obj_arch = "i386:x86-64" if is_pe32_plus else "i386"

    asm_tool = _which("as")
    ld_tool = _which("ld")
    objcopy = _which("objcopy")

    s_paths, bin_paths = _collect_sources(asm_path, data_path, asset_path)
    if not s_paths and not bin_paths:
        log.error(
            "win32_reassemble: no .s or .bin sources found — run "
            "`python -m splat split <yaml>` first"
        )

    # The splat-generated linker script references object files at
    # `<build_path>/<source_relpath><suffix>`. With splat's default
    # `o_as_suffix: False` the suffix is `.s.o` (`<source>.s.o`); with
    # `o_as_suffix: True` it's just `.o` (`<source>.o`). Match
    # whichever the YAML opted into.
    use_o_as_suffix = bool(opts.get("o_as_suffix", False))

    def _obj_for(src: Path) -> Path:
        for root in (asm_path, data_path):
            try:
                rel = src.relative_to(root)
                if use_o_as_suffix:
                    rel = rel.with_suffix(".o")
                else:
                    rel = rel.with_suffix(rel.suffix + ".o")
                return build_path / "asm" / rel
            except ValueError:
                continue
        return src.with_suffix(src.suffix + ".o")

    for s_path in s_paths:
        o_path = _obj_for(s_path)
        o_path.parent.mkdir(parents=True, exist_ok=True)
        _run([asm_tool, mode_flag, str(s_path), "-o", str(o_path)], verbose)

    # Wrap .bin assets so ld can link them. Splat's linker script
    # references each bin as `<build_path>/assets/<rel>.o` (no .bin
    # suffix), pulling the `.data` section that `objcopy -I binary`
    # populates by default. Run `objcopy` from `bin_path.parent` so
    # the embedded `_binary_<name>_start` symbols come out
    # deterministic regardless of where the source file lives.
    for bin_path in bin_paths:
        try:
            rel = bin_path.relative_to(asset_path)
        except ValueError:
            rel = Path(bin_path.name)
        o_rel = rel.with_suffix(".o")
        o_path = build_path / "assets" / o_rel
        o_path.parent.mkdir(parents=True, exist_ok=True)
        # objcopy from CWD=bin_path.parent so the auto-generated
        # `_binary_<basename>_start` symbol uses just the filename.
        _run(
            [
                objcopy,
                "-I",
                "binary",
                "-O",
                bin_obj_fmt,
                "-B",
                bin_obj_arch,
                bin_path.name,
                str(o_path.resolve()),
            ],
            verbose,
            cwd=bin_path.parent,
        )

    # Link via the splat-generated linker script. Run from base_path
    # so the script's `build/asm/...` references resolve.
    with tempfile.TemporaryDirectory(prefix="splat-reasm-") as td:
        elf_path = Path(td) / "linked.elf"
        # -N (omagic): produce an ELF without page-aligned segments —
        # the splat .ld layout packs sections contiguously by LMA and
        # would otherwise blow past the program-header capacity.
        _run(
            [
                ld_tool,
                "-m",
                ld_emulation,
                "-N",
                "-T",
                ld_path.name,
                "-o",
                str(elf_path),
            ],
            verbose,
            cwd=base_path,
        )
        # Force alloc/load on splat's custom .header section so the
        # binary extraction includes it. GAS marks .header as
        # READONLY-only because there's no exec/write flag in the
        # `.section .header` line; that's enough for the linker but
        # makes `-O binary` skip the bytes.
        _run(
            [
                objcopy,
                "--set-section-flags",
                ".header=alloc,load,data",
                str(elf_path),
            ],
            verbose,
        )
        # Extract the loaded image as a raw byte blob — the splat
        # `.header` section already contains the full PE header
        # (DOS stub + COFF + optional header + section table) and
        # every other section is positioned at its file-offset by
        # the linker script. Wrapping with `-O pei-*` would prepend
        # a second PE header; we just want the bytes verbatim.
        out_path.parent.mkdir(parents=True, exist_ok=True)
        _run(
            [objcopy, "-O", "binary", str(elf_path), str(out_path)],
            verbose,
        )

    if verbose:
        sha = hashlib.sha1(out_path.read_bytes()).hexdigest()
        print(f"Produced {out_path} ({len(out_path.read_bytes())} bytes, sha1 {sha})")

    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reassemble a splat-split Win32 PE back into a single .exe/.dll"
    )
    parser.add_argument("yaml", type=Path, help="splat YAML config")
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output PE path (defaults to <target>.reasm)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    conf = _read_yaml(args.yaml)
    target = conf["options"].get("target_path")
    out_path = args.out
    if out_path is None:
        if not target:
            log.error("win32_reassemble: YAML has no target_path; pass --out")
        base_path = (args.yaml.parent / conf["options"].get("base_path", ".")).resolve()
        out_path = Path(str((base_path / target).resolve()) + ".reasm")

    reassemble(args.yaml, out_path, verbose=args.verbose)


if __name__ == "__main__":
    main()
