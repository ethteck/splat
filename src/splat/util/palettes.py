from typing import Dict

from ..util import log

from ..segtypes.common.group import CommonSegGroup
from ..segtypes.n64.ci import N64SegCi
from ..segtypes.n64.palette import N64SegPalette

global_pal_ids: Dict[str, N64SegPalette]


# Resolve Raster#palette and Palette#raster links
def initialize(all_segments):
    def find_global_pal_ids(segments):
        for segment in segments:
            if isinstance(segment, N64SegPalette):
                if segment.pal_id is not None:
                    global_pal_ids[segment.pal_id] = segment

            if isinstance(segment, CommonSegGroup):
                find_global_pal_ids(segment.subsegments)

    def process(segments):
        raster_map: Dict[str, N64SegCi] = {}
        palette_map: Dict[str, N64SegPalette] = {}

        for segment in segments:
            if isinstance(segment, N64SegPalette):
                palette_map[segment.name] = segment

            if isinstance(segment, N64SegCi):
                raster_map[segment.name] = segment

            if isinstance(segment, CommonSegGroup):
                process(segment.subsegments)

        palettes_seen = set(palette_map.keys())

        for raster in raster_map.values():
            for pal_name in raster.palette_names:
                pal = global_pal_ids.get(pal_name, None)
                if pal is not None:
                    global_pal_ids_not_seen.discard(pal_name)
                    raster.palettes.append(pal)
                else:
                    pal = palette_map.get(pal_name, None)

                    if pal is not None:
                        palettes_seen.discard(pal_name)
                        raster.palettes.append(pal)
                    else:
                        log.error("Could not find pal")

            # Resolve "." palette links
            for pal_name in palette_map:
                if pal_name.startswith(raster.name + "."):
                    pal = palette_map[pal_name]
                    raster.palettes.append(pal)
                    palettes_seen.discard(pal_name)

        if len(palettes_seen) > 0:
            log.error(
                f"Found no ci links to palettes with names: {', '.join(palettes_seen)}"
            )

    global global_pal_ids
    global_pal_ids = {}

    find_global_pal_ids(all_segments)

    global_pal_ids_not_seen = set(global_pal_ids.keys())

    process(all_segments)

    if len(global_pal_ids_not_seen) > 0:
        log.error(
            f"Found no ci links to palettes with pal_ids: {', '.join(global_pal_ids_not_seen)}"
        )
