from segtypes.n64.img import N64SegImg
import n64img.image


class N64SegI8(N64SegImg):
    def __init__(self, *args, **kwargs):
        kwargs["img_cls"] = n64img.image.I8
        super().__init__(*args, **kwargs)
