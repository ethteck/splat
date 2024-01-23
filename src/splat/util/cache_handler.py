import pickle
from typing import Any, Dict

from . import options, log
from ..segtypes.common.segment import Segment


class Cache:
    def __init__(self, config: Dict[str, Any], use_cache: bool, verbose: bool):
        self.use_cache: bool = use_cache
        self.cache: Dict[str, Any] = {}

        # Load cache
        if use_cache and options.opts.cache_path.exists():
            try:
                with options.opts.cache_path.open("rb") as f3:
                    self.cache = pickle.load(f3)

                if verbose:
                    log.write(f"Loaded cache ({len(self.cache.keys())} items)")
            except Exception:
                log.write(
                    f"Not able to load cache file. Discarding old cache", status="warn"
                )

        # invalidate entire cache if options change
        if use_cache and self.cache.get("__options__") != config.get("options"):
            if verbose:
                log.write("Options changed, invalidating cache")

            self.cache = {
                "__options__": config.get("options"),
            }

    def save(self, verbose: bool):
        if self.cache != {} and self.use_cache:
            if verbose:
                log.write("Writing cache")
            options.opts.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with options.opts.cache_path.open("wb") as f4:
                pickle.dump(self.cache, f4)

    def check_cache_hit(self, segment: Segment, update_on_miss: bool) -> bool:
        if self.use_cache:
            cached = segment.cache()
            segment_id = segment.unique_id()

            if cached == self.cache.get(segment_id):
                # Cache hit
                return True

            # Cache miss
            if update_on_miss:
                self.cache[segment_id] = cached

        return False
