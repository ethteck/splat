from ..common.hasm import CommonSegHasm


class N64SegIpl3(CommonSegHasm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.special_vram_segment = True
