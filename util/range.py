from typing import Optional


class Range:
    def __init__(self, start: Optional[int] = None, end: Optional[int] = None):
        self.start: Optional[int] = start
        self.end: Optional[int] = end

    def has_start(self):
        return self.start is not None

    def has_end(self):
        return self.end is not None

    def is_complete(self):
        return self.has_start() and self.has_end()
