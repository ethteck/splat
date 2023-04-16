from split import *
import unittest
import io
import filecmp
import pprint


class Testing(unittest.TestCase):
    def compare_files(self, test_path, ref_path):
        with io.open(test_path) as test_f, io.open(ref_path) as ref_f:
            self.assertListEqual(list(test_f), list(ref_f))

    def get_same_files(self, dcmp, out):
        for name in dcmp.same_files:
            out.append((name, dcmp.left, dcmp.right))

        for sub_dcmp in dcmp.subdirs.values():
            self.get_same_files(sub_dcmp, out)

    def get_diff_files(self, dcmp, out):
        for name in dcmp.diff_files:
            out.append((name, dcmp.left, dcmp.right))

        for sub_dcmp in dcmp.subdirs.values():
            self.get_diff_files(sub_dcmp, out)

    def test_basic_app(self):
        main(["test/basic_app/splat.yaml"], None, None)

        comparison = filecmp.dircmp("test/basic_app/split", "test/basic_app/expected")

        diff_files: List[Tuple[str, str, str]] = []
        self.get_diff_files(comparison, diff_files)

        same_files: List[Tuple[str, str, str]] = []
        self.get_same_files(comparison, same_files)

        print("same_files", same_files)
        print("diff_files", diff_files)

        assert len(diff_files) == 0


if __name__ == "__main__":
    unittest.main()
