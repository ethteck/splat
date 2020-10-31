from segtypes.ci8palette import N64SegCi8palette

class N64SegCi4palette(N64SegCi8palette):
    # It's impossible for a CI-4 image to use more than 128 of the colors in its palette, but there are some images
    # that reference full-256-color palettes despite being in CI-4 format so this check can't be made.
    """
    def max_length(self):
        if self.compressed: return None
        return 128 * 2
    """
