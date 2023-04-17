class Disassembler:
    def configure(self, options):
        raise NotImplementedError("configure")

    def check_version(self, skip_version_check, splat_version):
        raise NotImplementedError("check_version")

    def known_types(self):
        raise NotImplementedError("known_types")
