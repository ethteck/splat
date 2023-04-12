from split import *
import unittest
import io


class Testing(unittest.TestCase):
    def compare_files(self, test_path, ref_path):
        with io.open(test_path) as test_f, io.open(ref_path) as ref_f:
            self.assertListEqual(list(test_f), list(ref_f))

    def test_basic_app(self):
        main(["test/basic_app/splat.yaml"], None, None)

        self.compare_files(
            "test/basic_app/split/src/main.c", "test/basic_app/expected/main.c"
        )

        self.compare_files(
            "test/basic_app/split/asm/nonmatchings/main/func_004001DC.s",
            "test/basic_app/expected/func_004001DC.s",
        )


if __name__ == "__main__":
    unittest.main()
