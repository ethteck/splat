from segtypes.n64.img import N64SegImg
import n64img.image


class N64SegIa4(N64SegImg):
    def __init__(self, *args, **kwargs):
        kwargs["img_cls"] = n64img.image.IA4
        super().__init__(*args, **kwargs)
