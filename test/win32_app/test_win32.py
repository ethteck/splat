"""Stand-alone smoke test for the win32 platform.

Regenerates the synthetic PE32 fixture, runs splat against it, and checks
that the expected output files were produced. Designed to be invoked
either directly (``python test/win32_app/test_win32.py``) or via the
top-level ``test.py``.
"""

from pathlib import Path
import shutil
import sys
import unittest

THIS_DIR = Path(__file__).parent
REPO_ROOT = THIS_DIR.parent.parent
sys.path.insert(0, str(REPO_ROOT))


class Win32App(unittest.TestCase):
    def setUp(self):
        # Regenerate the binary so the test is hermetic.
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "_win32_generate", THIS_DIR / "generate.py"
        )
        generate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generate)
        generate.main()

        out_root = THIS_DIR / "split"
        if out_root.exists():
            shutil.rmtree(out_root)

    def test_split_runs_and_emits_expected_files(self):
        from src.splat.scripts.split import main as splat_main

        splat_main([THIS_DIR / "splat.yaml"], None, False)

        out_root = THIS_DIR / "split"
        expected_paths = [
            out_root / "asm" / "header.s",
            out_root / "asm" / "main_text.s",
            out_root / "win32_app.ld",
        ]
        for path in expected_paths:
            self.assertTrue(path.exists(), f"missing expected output: {path}")

        # Sanity-check the disassembly: the entry instructions for `main`
        # should always decode to the same sequence.
        text = (out_root / "asm" / "main_text.s").read_text(encoding="utf-8")
        for needle in ("push ebp", "mov ebp, esp", "mov eax, 0x2a", "ret"):
            self.assertIn(needle, text, f"win32 disasm missing '{needle}'")

        # Header must round-trip the PE signature and section names.
        header = (out_root / "asm" / "header.s").read_text(encoding="utf-8")
        for needle in (
            '.ascii "MZ"',
            '.ascii "PE\\0\\0"',
            '.ascii ".text',
            '.ascii ".data',
            '.ascii ".bss',
        ):
            self.assertIn(needle, header, f"win32 header missing {needle!r}")

        # Linker script must mention the segments we declared.
        ld = (out_root / "win32_app.ld").read_text(encoding="utf-8")
        for needle in ("header", "main_text", "main_data", "bss"):
            self.assertIn(needle, ld, f"linker script missing {needle!r}")

    def test_exact_encoding_byte_identical(self):
        """`exact_encoding: true` on a text subsegment must produce a
        byte-identical .text after assembly."""
        import shutil as _shutil
        import subprocess as _sub

        if _shutil.which("as") is None or _shutil.which("objcopy") is None:
            self.skipTest("`as`/`objcopy` not installed")

        out_root = THIS_DIR / "split-exact"
        if out_root.exists():
            shutil.rmtree(out_root)

        # Write an alternate yaml with exact_encoding enabled.
        exact_yaml = THIS_DIR / "splat-exact.yaml"
        exact_yaml.write_text(
            (THIS_DIR / "splat.yaml")
            .read_text(encoding="utf-8")
            .replace("base_path: split", "base_path: split-exact")
            .replace(
                "[0x200, text, main_text]",
                "{ start: 0x200, type: text, name: main_text, exact_encoding: true }",
            )
        )

        from src.splat.scripts.split import main as splat_main

        splat_main([exact_yaml], None, False)

        asm = out_root / "asm/main_text.s"
        obj = THIS_DIR / "main_text.o"
        binf = THIS_DIR / "main_text.bin"
        try:
            r = _sub.run(["as", "--32", str(asm), "-o", str(obj)], capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr.decode())
            r = _sub.run(
                ["objcopy", "-O", "binary", "-j", ".text", str(obj), str(binf)],
                capture_output=True,
            )
            self.assertEqual(r.returncode, 0, r.stderr.decode())
            orig = (THIS_DIR / "win32_app.exe").read_bytes()[0x200 : 0x200 + 0x11]
            reasm = binf.read_bytes()[: len(orig)]
            self.assertEqual(
                orig, reasm, "exact_encoding text bytes diverge from original"
            )
        finally:
            for p in (obj, binf, exact_yaml):
                if p.exists():
                    p.unlink()
            if out_root.exists():
                _shutil.rmtree(out_root)


if __name__ == "__main__":
    unittest.main()
