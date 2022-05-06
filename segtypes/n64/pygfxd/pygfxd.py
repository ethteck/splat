#!/usr/bin/env python3
#
#   Python bindings for libgfxd
#   https://github.com/glankk/libgfxd/
#

import io, os, struct
from enum import IntEnum, auto
from ctypes import Structure, CFUNCTYPE, POINTER, create_string_buffer, byref, CDLL, c_void_p, c_char_p, c_uint32, c_int32, c_int, c_ubyte
from typing import Callable, Tuple

# ====================================================================
#   Library Internals
# ====================================================================

def uint_to_sint(u):
    return struct.unpack(">i", struct.pack(">I", u))[0]

def uint_bits_to_float(u):
    return struct.unpack(">f", struct.pack(">I", u))[0]

# target types
class gfx_ucode(Structure):
    _fields_=[("disas_fn",  CFUNCTYPE(c_void_p, c_int32, c_int32)),
              ("combine_fn", CFUNCTYPE(c_void_p, c_int)),
              ("arg_tbl",   c_void_p),
              ("macro_tbl", c_void_p)]

gfx_ucode_t = POINTER(gfx_ucode)

# argument errors
class GfxdArgumentError(Exception):
    """
    Exception raised for errors in gfxd function arguments.

    Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, expression, message):
        self.expression = expression
        self.message = message

# gross way to prevent garbage collection of wrapped callbacks and buffers
__gfxd_buffers_callbacks = {}

def free_buffers_callbacks():
    __gfxd_buffers_callbacks.clear()

# Load the shared library into ctypes
lgfxd = CDLL(os.path.dirname(os.path.realpath(__file__)) + os.sep + "libgfxd.so")

# ====================================================================
#   Constants
# ====================================================================

# target ucodes, loaded from dynamic library
gfxd_f3db   = gfx_ucode_t.in_dll(lgfxd, "gfxd_f3db")
gfxd_f3d    = gfx_ucode_t.in_dll(lgfxd, "gfxd_f3d")
gfxd_f3dexb = gfx_ucode_t.in_dll(lgfxd, "gfxd_f3dexb")
gfxd_f3dex  = gfx_ucode_t.in_dll(lgfxd, "gfxd_f3dex")
gfxd_f3dex2 = gfx_ucode_t.in_dll(lgfxd, "gfxd_f3dex2")

# endian
class GfxdEndian(IntEnum):
    """ gfxd_endian_* """
    big = auto()
    little = auto()
    host = auto()

# cap
class GfxdCap(IntEnum):
    """ gfxd_* """
    stop_on_invalid = auto()
    stop_on_end = auto()
    emit_dec_color = auto()
    emit_q_macro = auto()
    emit_ext_macro = auto()

# arg format
class GfxdArgfmt(IntEnum):
    """ gfxd_argfmt_* """
    i = auto()
    u = auto()
    f = auto()

# macro ids
class GfxdMacroId(IntEnum):
    """ gfxd_* """
    Invalid = auto()
    DPFillRectangle = auto()
    DPFullSync = auto()
    DPLoadSync = auto()
    DPTileSync = auto()
    DPPipeSync = auto()
    DPLoadTLUT_pal16 = auto()
    DPLoadTLUT_pal256 = auto()
    DPLoadMultiBlockYuvS = auto()
    DPLoadMultiBlockYuv = auto()
    DPLoadMultiBlock_4bS = auto()
    DPLoadMultiBlock_4b = auto()
    DPLoadMultiBlockS = auto()
    DPLoadMultiBlock = auto()
    _DPLoadTextureBlockYuvS = auto()
    _DPLoadTextureBlockYuv = auto()
    _DPLoadTextureBlock_4bS = auto()
    _DPLoadTextureBlock_4b = auto()
    _DPLoadTextureBlockS = auto()
    _DPLoadTextureBlock = auto()
    DPLoadTextureBlockYuvS = auto()
    DPLoadTextureBlockYuv = auto()
    DPLoadTextureBlock_4bS = auto()
    DPLoadTextureBlock_4b = auto()
    DPLoadTextureBlockS = auto()
    DPLoadTextureBlock = auto()
    DPLoadMultiTileYuv = auto()
    DPLoadMultiTile_4b = auto()
    DPLoadMultiTile = auto()
    _DPLoadTextureTileYuv = auto()
    _DPLoadTextureTile_4b = auto()
    _DPLoadTextureTile = auto()
    DPLoadTextureTileYuv = auto()
    DPLoadTextureTile_4b = auto()
    DPLoadTextureTile = auto()
    DPLoadBlock = auto()
    DPNoOp = auto()
    DPNoOpTag = auto()
    DPPipelineMode = auto()
    DPSetBlendColor = auto()
    DPSetEnvColor = auto()
    DPSetFillColor = auto()
    DPSetFogColor = auto()
    DPSetPrimColor = auto()
    DPSetColorImage = auto()
    DPSetDepthImage = auto()
    DPSetTextureImage = auto()
    DPSetAlphaCompare = auto()
    DPSetAlphaDither = auto()
    DPSetColorDither = auto()
    DPSetCombineMode = auto()
    DPSetCombineLERP = auto()
    DPSetConvert = auto()
    DPSetTextureConvert = auto()
    DPSetCycleType = auto()
    DPSetDepthSource = auto()
    DPSetCombineKey = auto()
    DPSetKeyGB = auto()
    DPSetKeyR = auto()
    DPSetPrimDepth = auto()
    DPSetRenderMode = auto()
    DPSetScissor = auto()
    DPSetScissorFrac = auto()
    DPSetTextureDetail = auto()
    DPSetTextureFilter = auto()
    DPSetTextureLOD = auto()
    DPSetTextureLUT = auto()
    DPSetTexturePersp = auto()
    DPSetTile = auto()
    DPSetTileSize = auto()
    SP1Triangle = auto()
    SP2Triangles = auto()
    SP1Quadrangle = auto()
    SPBranchLessZ = auto()
    SPBranchLessZrg = auto()
    SPBranchList = auto()
    SPClipRatio = auto()
    SPCullDisplayList = auto()
    SPDisplayList = auto()
    SPEndDisplayList = auto()
    SPFogPosition = auto()
    SPForceMatrix = auto()
    SPSetGeometryMode = auto()
    SPClearGeometryMode = auto()
    SPLoadGeometryMode = auto()
    SPInsertMatrix = auto()
    SPLine3D = auto()
    SPLineW3D = auto()
    SPLoadUcode = auto()
    SPLookAtX = auto()
    SPLookAtY = auto()
    SPLookAt = auto()
    SPMatrix = auto()
    SPModifyVertex = auto()
    SPPerspNormalize = auto()
    SPPopMatrix = auto()
    SPPopMatrixN = auto()
    SPSegment = auto()
    SPSetLights1 = auto()
    SPSetLights2 = auto()
    SPSetLights3 = auto()
    SPSetLights4 = auto()
    SPSetLights5 = auto()
    SPSetLights6 = auto()
    SPSetLights7 = auto()
    SPNumLights = auto()
    SPLight = auto()
    SPLightColor = auto()
    SPTexture = auto()
    SPTextureRectangle = auto()
    SPTextureRectangleFlip = auto()
    SPVertex = auto()
    SPViewport = auto()
    DPLoadTLUTCmd = auto()
    DPLoadTLUT = auto()
    BranchZ = auto()
    DisplayList = auto()
    DPHalf1 = auto()
    DPHalf2 = auto()
    DPLoadTile = auto()
    SPGeometryMode = auto()
    SPSetOtherModeLo = auto()
    SPSetOtherModeHi = auto()
    DPSetOtherMode = auto()
    MoveWd = auto()
    MoveMem = auto()
    SPDma_io = auto()
    SPDmaRead = auto()
    SPDmaWrite = auto()
    LoadUcode = auto()
    SPLoadUcodeEx = auto()
    TexRect = auto()
    TexRectFlip = auto()
    SPNoOp = auto()
    Special3 = auto()
    Special2 = auto()
    Special1 = auto()

# argument types
class GfxdArgType(IntEnum):
    """ gfxd_* """
    Word = auto()
    Opcode = auto()
    Coordi = auto()
    Coordq = auto()
    Pal = auto()
    Tlut = auto()
    Timg = auto()
    Tmem = auto()
    Tile = auto()
    Fmt = auto()
    Siz = auto()
    Dim = auto()
    Cm = auto()
    Tm = auto()
    Ts = auto()
    Dxt = auto()
    Tag = auto()
    Pm = auto()
    Colorpart = auto()
    Color = auto()
    Lodfrac = auto()
    Cimg = auto()
    Zimg = auto()
    Ac = auto()
    Ad = auto()
    Cd = auto()
    Ccpre = auto()
    Ccmuxa = auto()
    Ccmuxb = auto()
    Ccmuxc = auto()
    Ccmuxd = auto()
    Acmuxabd = auto()
    Acmuxc = auto()
    Cv = auto()
    Tc = auto()
    Cyc = auto()
    Zs = auto()
    Ck = auto()
    Keyscale = auto()
    Keywidth = auto()
    Zi = auto()
    Rm1 = auto()
    Rm2 = auto()
    Sc = auto()
    Td = auto()
    Tf = auto()
    Tl = auto()
    Tt = auto()
    Tp = auto()
    Line = auto()
    Vtx = auto()
    Vtxflag = auto()
    Dl = auto()
    Zraw = auto()
    Dlflag = auto()
    Cr = auto()
    Num = auto()
    Fogz = auto()
    Fogp = auto()
    Mtxptr = auto()
    Gm = auto()
    Mwo_matrix = auto()
    Linewd = auto()
    Uctext = auto()
    Ucdata = auto()
    Size = auto()
    Lookatptr = auto()
    Mtxparam = auto()
    Mtxstack = auto()
    Mwo_point = auto()
    Wscale = auto()
    Seg = auto()
    Segptr = auto()
    Lightsn = auto()
    Numlights = auto()
    Lightnum = auto()
    Lightptr = auto()
    Tcscale = auto()
    Switch = auto()
    St = auto()
    Stdelta = auto()
    Vtxptr = auto()
    Vpptr = auto()
    Dram = auto()
    Sftlo = auto()
    Othermodelo = auto()
    Sfthi = auto()
    Othermodehi = auto()
    Mw = auto()
    Mwo = auto()
    Mwo_clip = auto()
    Mwo_lightcol = auto()
    Mv = auto()
    Mvo = auto()
    Dmem = auto()
    Dmaflag = auto()

# ====================================================================
#   Input/output Methods
# ====================================================================

lgfxd.gfxd_input_buffer.argtypes = [c_void_p, c_int]
lgfxd.gfxd_input_buffer.restype = None
def gfxd_input_buffer(buf: bytes, size: int = -1) -> c_void_p:
    """
    Read input from the buffer pointed to by buf, of size bytes.
    If size is negative, len(buf) is used instead which is
    default.
    """
    size = len(buf) if size < 0 else size

    buffer = create_string_buffer(buf, size)
    __gfxd_buffers_callbacks.update({100 : buffer})
    lgfxd.gfxd_input_buffer(buffer, size)
    return buffer

lgfxd.gfxd_output_buffer.argtypes = [c_char_p, c_int]
lgfxd.gfxd_output_buffer.restype = None
def gfxd_output_buffer(buf: bytes, size: int = -1) -> c_void_p:
    """
    Output to the buffer pointed to by buf, of size bytes.
    If size is negative, len(buf) is used instead which is
    default.
    """
    size = len(buf) if size < 0 else size

    buffer = create_string_buffer(buf, size)
    __gfxd_buffers_callbacks.update({101 : buffer})
    lgfxd.gfxd_output_buffer(buffer, size)
    return buffer

lgfxd.gfxd_input_fd.argtypes = [c_int]
lgfxd.gfxd_input_fd.restype = None
def gfxd_input_fd(stream: io.IOBase) -> None:
    """
    Read input from the provided stream implementing IOBase
    """
    lgfxd.gfxd_input_fd(stream.fileno())

lgfxd.gfxd_output_fd.argtypes = [c_int]
lgfxd.gfxd_output_fd.restype = None
def gfxd_output_fd(stream: io.IOBase) -> None:
    """
    Output to the provided stream implementing IOBase
    """
    lgfxd.gfxd_output_fd(stream.fileno())

lgfxd.gfxd_input_callback.argtypes = [CFUNCTYPE(c_int, c_void_p, c_int)]
lgfxd.gfxd_input_callback.restype = None
def gfxd_input_callback(fn: Callable[[bytes, int], int]) -> None:
    """
    Use the provided callback function, fn, compatible with the C function type
        int gfxd_input_fn_t(void *buf, int count)

    fn should copy at most count bytes to/from buf, and return the number of bytes actually copied.
    The input callback should return 0 to signal end of input.
    """
    cb =  CFUNCTYPE(c_int, c_void_p, c_int)(fn)
    __gfxd_buffers_callbacks.update({102 : cb})
    lgfxd.gfxd_macro_fn(cb)

lgfxd.gfxd_output_callback.argtypes = [CFUNCTYPE(c_int, c_char_p, c_int)]
lgfxd.gfxd_output_callback.restype = None
def gfxd_output_callback(fn: Callable[[bytes, int], int]) -> None:
    """
    Use the provided callback function, fn, compatible with C function type
        int gfxd_output_fn_t(const char *buf, int count)

    fn should copy at most count bytes to/from buf, and return the number of bytes actually copied.
    """
    cb = CFUNCTYPE(c_int, c_char_p, c_int)(fn)
    __gfxd_buffers_callbacks.update({103 : cb})
    lgfxd.gfxd_macro_fn(cb)

# ====================================================================
#   Handlers
# ====================================================================

lgfxd.gfxd_macro_dflt.argtypes = None
lgfxd.gfxd_macro_dflt.restype = c_int
def gfxd_macro_dflt() -> int:
    """
    The default macro handler. Outputs the macro name, dynamic display list
    pointer if one has been specified, and then each argument in order using
    the function registered using gfxd_arg_fn (gfxd_arg_dflt by default),
    and returns zero.

    Because it is designed to be extended, it only outputs the macro text, without
    any whitespace or punctuation before or after. When this function is used as
    the sole macro handler, it will output the entire display list on one line
    without any separation between macros, which is probably not what you want.
    """
    return lgfxd.gfxd_macro_dflt()

lgfxd.gfxd_macro_fn.argtypes = [CFUNCTYPE(c_int)]
lgfxd.gfxd_macro_fn.restype = None
def gfxd_macro_fn(fn: Callable[[], int]) -> None:
    """
    Set fn to be the macro handler function, compatible with the C function type
        int gfxd_macro_fn_t(void)

    fn can be None, in which case the handler is reset to the default.
    """
    if fn is None:
        lgfxd.gfxd_macro_fn(None)
    else:
        cb = CFUNCTYPE(c_int)(fn)
        __gfxd_buffers_callbacks.update({1000 : cb})
        lgfxd.gfxd_macro_fn(cb)

lgfxd.gfxd_arg_dflt.argtypes = [c_int]
lgfxd.gfxd_arg_dflt.restype = None
def gfxd_arg_dflt(arg_num: int) -> None:
    """
    The default argument handler for gfxd_macro_dflt.
    For the argument with index arg_num, calls gfxd_arg_callbacks, and prints
    the argument value if the callback returns zero, or if there is no
    callback for the given argument.
    """
    lgfxd.gfxd_arg_dflt(arg_num)

lgfxd.gfxd_arg_fn.argtypes = [CFUNCTYPE(c_int)]
lgfxd.gfxd_arg_fn.restype = None
def gfxd_arg_fn(fn: Callable[[], int]) -> None:
    """
    Set fn to be the argument handler function, called by gfxd_macro_dflt, for each
    argument in the current macro, not counting the dynamic display list pointer if
    one has been specified. fn should be compatible with the C function type
        void gfxd_arg_fn_t(int arg_num)

    fn can be None, in which case the handler is reset to
    the default. This only affects the output of gfxd_macro_dflt, and has no
    observable effect if gfxd_macro_dflt is overridden (not extended).
    """
    if fn is None:
        lgfxd.gfxd_arg_fn(None)
        return
    cb = CFUNCTYPE(c_int)(fn)
    __gfxd_buffers_callbacks.update({1001 : cb})
    lgfxd.gfxd_arg_fn(cb)

# ====================================================================
#   Argument Callbacks
# ====================================================================

lgfxd.gfxd_arg_callbacks.argtypes = [c_int]
lgfxd.gfxd_arg_callbacks.restype = c_int
def gfxd_arg_callbacks(arg_num: int) -> int:
    """
    Examines the argument with index arg_num and executes the callback function for
    that argument type, if such a callback is supported and has been registered.
    This function returns the value that was returned by the callback function.
    If no callback function has been registered for the argument type, zero is returned.

    Most argument callbacks have some extra parameters containing information that
    might be relevant to the argument that triggered the callback. The extra information
    is extracted only from the current macro, as gfxd does not retain any context
    information from previous or subsequent macros. If any of the extra parameter values
    is not available in the current macro, the value for that parameter is substituted
    with -1 for signed parameters, and zero for unsigned parameters.
    """
    return lgfxd.gfxd_arg_callbacks(arg_num)

lgfxd.gfxd_tlut_callback.argtypes = [CFUNCTYPE(c_int, c_uint32, c_int32, c_int32)]
lgfxd.gfxd_tlut_callback.restype = None
def gfxd_tlut_callback(fn: Callable[[int, int, int], int]) -> None:
    """
    Set the callback function for palette arguments, compatible with the C function type
        int gfxd_tlut_fn_t(uint32_t tlut, int32_t idx, int32_t count)

    The argument type is GfxdArgType.Tlut.

    The palette index is in idx and the number of colors in count.
    """
    cb = CFUNCTYPE(c_int, c_uint32, c_int32, c_int32)(fn)
    __gfxd_buffers_callbacks.update({0 : cb})
    lgfxd.gfxd_tlut_callback(cb)

lgfxd.gfxd_timg_callback.argtypes = [CFUNCTYPE(c_int, c_uint32, c_int32, c_int32, c_int32, c_int32, c_int32)]
lgfxd.gfxd_timg_callback.restype = None
def gfxd_timg_callback(fn: Callable[[int, int, int, int, int, int], int]) -> None:
    """
    Set the callback function for texture arguments, compatible with the C function type
        int gfxd_timg_fn_t(uint32_t timg, int32_t fmt, int32_t siz, int32_t width, int32_t height, int32_t pal)

    The argument type is GfxdArgType.Timg.

    The image format is in fmt and siz, the dimensions in width and height, and the
    palette index in pal.
    """
    cb = CFUNCTYPE(c_int, c_uint32, c_int32, c_int32, c_int32, c_int32, c_int32)(fn)
    __gfxd_buffers_callbacks.update({1 : cb})
    lgfxd.gfxd_timg_callback(cb)

lgfxd.gfxd_cimg_callback.argtypes = [CFUNCTYPE(c_int, c_uint32, c_int32, c_int32, c_int32)]
lgfxd.gfxd_cimg_callback.restype = None
def gfxd_cimg_callback(fn: Callable[[int, int, int, int], int]) -> None:
    """
    Set the callback function for frame buffer arguments, compatible with the C function type
        int gfxd_cimg_fn_t(uint32_t cimg, int32_t fmt, int32_t siz, int32_t width)

    The argument type is GfxdArgType.Cimg.

    The image format is in fmt and siz, and the horizontal resolution in width.
    """
    cb = CFUNCTYPE(c_int, c_uint32, c_int32, c_int32, c_int32)(fn)
    __gfxd_buffers_callbacks.update({2 : cb})
    lgfxd.gfxd_cimg_callback(cb)

lgfxd.gfxd_zimg_callback.argtypes = [CFUNCTYPE(c_int, c_uint32)]
lgfxd.gfxd_zimg_callback.restype = None
def gfxd_zimg_callback(fn: Callable[[int], int]) -> None:
    """
    Set the callback function for depth buffer arguments, compatible with the C function type
        int gfxd_zimg_fn_t(uint32_t zimg)

    The argument type is GfxdArgType.Zimg.
    """
    cb = CFUNCTYPE(c_int, c_uint32)(fn)
    __gfxd_buffers_callbacks.update({3 : cb})
    lgfxd.gfxd_zimg_callback(cb)

lgfxd.gfxd_dl_callback.argtypes = [CFUNCTYPE(c_int, c_uint32)]
lgfxd.gfxd_dl_callback.restype = None
def gfxd_dl_callback(fn: Callable[[int], int]) -> None:
    """
    Set the callback function for display list arguments, compatible with the C function type
        int gfxd_dl_fn_t(uint32_t dl)

    The argument type is GfxdArgType.Dl.
    """
    cb = CFUNCTYPE(c_int, c_uint32)(fn)
    __gfxd_buffers_callbacks.update({4 : cb})
    lgfxd.gfxd_dl_callback(cb)

lgfxd.gfxd_mtx_callback.argtypes = [CFUNCTYPE(c_int, c_uint32)]
lgfxd.gfxd_mtx_callback.restype = None
def gfxd_mtx_callback(fn: Callable[[int], int]) -> None:
    """
    Set the callback function for matrix arguments, compatible with the C function type
        int gfxd_mtx_fn_t(uint32_t mtx)

    The argument type is GfxdArgType.Mtxptr.
    """
    cb = CFUNCTYPE(c_int, c_uint32)(fn)
    __gfxd_buffers_callbacks.update({5 : cb})
    lgfxd.gfxd_mtx_callback(cb)

lgfxd.gfxd_lookat_callback.argtypes = [CFUNCTYPE(c_int, c_uint32, c_int32)]
lgfxd.gfxd_lookat_callback.restype = None
def gfxd_lookat_callback(fn: Callable[[int, int], int]) -> None:
    """
    Set the callback function for lookat array arguments, compatible with the C function type
        int gfxd_lookat_fn_t(uint32_t lookat, int32_t count)

    The argument type is GfxdArgType.Lookatptr.

    The number of lookat structures (1 or 2) is in count.
    """
    cb = CFUNCTYPE(c_int, c_uint32, c_int32)(fn)
    __gfxd_buffers_callbacks.update({6 : cb})
    lgfxd.gfxd_lookat_callback(cb)

lgfxd.gfxd_light_callback.argtypes = [CFUNCTYPE(c_int, c_uint32, c_int32)]
lgfxd.gfxd_light_callback.restype = None
def gfxd_light_callback(fn: Callable[[int, int], int]) -> None:
    """
    Set the callback function for light array arguments.
        int gfxd_light_fn_t(uint32_t light, int32_t count)

    The argument type is GfxdArgType.Lightptr.

    The number of light structures is in count.
    """
    cb = CFUNCTYPE(c_int, c_uint32, c_int32)(fn)
    __gfxd_buffers_callbacks.update({7 : cb})
    lgfxd.gfxd_light_callback(cb)

lgfxd.gfxd_seg_callback.argtypes = [CFUNCTYPE(c_int, c_uint32, c_int32)]
lgfxd.gfxd_seg_callback.restype = None
def gfxd_seg_callback(fn: Callable[[int, int], int]) -> None:
    """
    Set the callback function for segment base arguments, compatible with the C function type
        int gfxd_seg_fn_t(uint32_t seg, int32_t num)

    The argument type is GfxdArgType.Segptr.

    The segment number is in num.
    """
    cb = CFUNCTYPE(c_int, c_uint32, c_int32)(fn)
    __gfxd_buffers_callbacks.update({8 : cb})
    lgfxd.gfxd_seg_callback(cb)

lgfxd.gfxd_vtx_callback.argtypes = [CFUNCTYPE(c_int, c_uint32, c_int32)]
lgfxd.gfxd_vtx_callback.restype = None
def gfxd_vtx_callback(fn: Callable[[int, int], int]) -> None:
    """
    Set the callback function for vertex array arguments, compatible with the C function type
        int gfxd_vtx_fn_t(uint32_t vtx, int32_t num)

    The argument type is GfxdArgType.Vtxptr.

    The number of vertex structures is in num.
    """
    cb = CFUNCTYPE(c_int, c_uint32, c_int32)(fn)
    __gfxd_buffers_callbacks.update({9 : cb})
    lgfxd.gfxd_vtx_callback(cb)

lgfxd.gfxd_vp_callback.argtypes = [CFUNCTYPE(c_int, c_uint32)]
lgfxd.gfxd_vp_callback.restype = None
def gfxd_vp_callback(fn: Callable[[int], int]) -> None:
    """
    Set the callback function for viewport arguments, compatible with the C function type
        int gfxd_vp_fn_t(uint32_t vp)

    The argument type is GfxdArgType.Vp.
    """
    cb = CFUNCTYPE(c_int, c_uint32)(fn)
    __gfxd_buffers_callbacks.update({10 : cb})
    lgfxd.gfxd_vp_callback(cb)

lgfxd.gfxd_uctext_callback.argtypes = [CFUNCTYPE(c_int, c_uint32, c_uint32)]
lgfxd.gfxd_uctext_callback.restype = None
def gfxd_uctext_callback(fn: Callable[[int, int], int]) -> None:
    """
    Set the callback function for microcode text arguments, compatible with the C function type
        int gfxd_uctext_fn_t(uint32_t text, uint32_t size)

    The argument type is GfxdArgType.Uctext.

    The size of the text segment is in size.
    """
    cb = CFUNCTYPE(c_int, c_uint32, c_uint32)(fn)
    __gfxd_buffers_callbacks.update({11 : cb})
    lgfxd.gfxd_uctext_callback(cb)

lgfxd.gfxd_ucdata_callback.argtypes = [CFUNCTYPE(c_int, c_uint32, c_uint32)]
lgfxd.gfxd_ucdata_callback.restype = None
def gfxd_ucdata_callback(fn: Callable[[int, int], int]) -> None:
    """
    Set the callback function for microcode data arguments, compatible with the C function type
        int gfxd_ucdata_fn_t(uint32_t data, uint32_t size)

    The argument type is GfxdArgType.Ucdata.

    The size of the data segment is in size.
    """
    cb = CFUNCTYPE(c_int, c_uint32, c_uint32)(fn)
    __gfxd_buffers_callbacks.update({12 : cb})
    lgfxd.gfxd_ucdata_callback(cb)

lgfxd.gfxd_dram_callback.argtypes = [CFUNCTYPE(c_int, c_uint32, c_uint32)]
lgfxd.gfxd_dram_callback.restype = None
def gfxd_dram_callback(fn: Callable[[int, int], int]) -> None:
    """
    Set the callback function for generic pointer arguments, compatible with the C function type
        int gfxd_dram_fn_t(uint32_t dram, uint32_t size)

    The argument type is GfxdArgType.Dram.

    The size of the data is in size.
    """
    cb = CFUNCTYPE(c_int, c_uint32, c_uint32)(fn)
    __gfxd_buffers_callbacks.update({13 : cb})
    lgfxd.gfxd_dram_callback(cb)

# ====================================================================
#   General Settings
# ====================================================================

lgfxd.gfxd_target.argtypes = [gfx_ucode_t]
lgfxd.gfxd_target.restype = None
def gfxd_target(target: gfx_ucode_t) -> None:
    """
    Select ucode as the target microcode.

    ucode can be
        gfxd_f3d
        gfxd_f3db
        gfxd_f3dex
        gfxd_f3dexb
        gfxd_f3dex2

    The microcode must be selected before gfxd_execute, as no microcode is selected by default.
    """
    lgfxd.gfxd_target(target)

lgfxd.gfxd_endian.argtypes = [c_int, c_int]
lgfxd.gfxd_endian.restype = None
def gfxd_endian(endian: GfxdEndian, wordsize: int) -> None:
    """
    Select endian as the endianness of the input, and wordsize as the size of each word in number of bytes.

    endian can be
        GfxdEndian.big
        GfxdEndian.little
        GfxdEndian.host (the endianness of the host machine)

    wordsize can be 1, 2, 4, or 8. Big endian is selected by default, with a word size of 4.
    """
    lgfxd.gfxd_endian(int(endian), wordsize)

lgfxd.gfxd_dynamic.argtypes = [c_char_p]
lgfxd.gfxd_dynamic.restype = None
def gfxd_dynamic(arg: str) -> None:
    """
    Enable or disable the use of dynamic g macros instead of static gs macros, and select the dynamic display list pointer argument to be used.
    arg will be used by gfxd_macro_dflt as the first argument to dynamic macros.

    If arg is None, dynamic macros are disabled, and gs macros are used.

    Also affects the result of gfxd_macro_name, as it will return either the dynamic or static version of the macro name as selected by this setting.
    """
    if arg is None:
        lgfxd.gfxd_dynamic(None)
        return None
    # we want to keep this string around for a while, so buffer it
    buffer = create_string_buffer(arg.encode("utf-8"), len(arg.encode("utf-8")))
    __gfxd_buffers_callbacks.update({10000 : buffer})
    lgfxd.gfxd_dynamic(buffer)

lgfxd.gfxd_enable.argtypes = [c_int]
lgfxd.gfxd_enable.restype = None
def gfxd_enable(cap: GfxdCap) -> None:
    """
    Enable the feature specified by cap. Can be one of the following;

        GfxdCap.stop_on_invalid:
                Stop execution when encountering an invalid macro. Enabled by default.
        GfxdCap.stop_on_end:
                Stop execution when encountering a SPBranchList or SPEndDisplayList. Enabled by default.
        GfxdCap.emit_dec_color:
                Print color components as decimal instead of hexadecimal. Disabled by default.
        GfxdCap.emit_q_macro:
                Print fixed-point conversion q macros for fixed-point values. Disabled by default.
        GfxdCap.emit_ext_macro:
                Emit non-standard macros. Some commands are valid (though possibly meaningless), but have no macros associated with them,
                such as a standalone G_RDPHALF_1. When this feature is enabled, such a command will produce a non-standard gsDPHalf1
                macro instead of a raw hexadecimal command. Also enables some non-standard multi-packet texture loading macros. Disabled
                by default.
    """
    lgfxd.gfxd_enable(int(cap))

lgfxd.gfxd_disable.argtypes = [c_int]
lgfxd.gfxd_disable.restype = None
def gfxd_disable(cap: GfxdCap) -> None:
    """
    Disable the feature specified by cap. Can be one of the following;

        GfxdCap.stop_on_invalid:
                Stop execution when encountering an invalid macro. Enabled by default.
        GfxdCap.stop_on_end:
                Stop execution when encountering a SPBranchList or SPEndDisplayList. Enabled by default.
        GfxdCap.emit_dec_color:
                Print color components as decimal instead of hexadecimal. Disabled by default.
        GfxdCap.emit_q_macro:
                Print fixed-point conversion q macros for fixed-point values. Disabled by default.
        GfxdCap.emit_ext_macro:
                Emit non-standard macros. Some commands are valid (though possibly meaningless), but have no macros associated with them,
                such as a standalone G_RDPHALF_1. When this feature is enabled, such a command will produce a non-standard gsDPHalf1
                macro instead of a raw hexadecimal command. Also enables some non-standard multi-packet texture loading macros. Disabled
                by default.
    """
    lgfxd.gfxd_disable(int(cap))

lgfxd.gfxd_udata_set.argtypes = [c_void_p]
lgfxd.gfxd_udata_set.restype = None
def gfxd_udata_set(p: c_void_p) -> None:
    """
    Set a generic pointer that can be used to pass user-defined data in and out of callback functions.

    The data should be appropriately wrapped with ctypes by the user.
    """
    lgfxd.gfxd_udata_set(p)

lgfxd.gfxd_udata_set.argtypes = None
lgfxd.gfxd_udata_set.restype = c_void_p
def gfxd_udata_get() -> c_void_p:
    """
    Get the generic pointer that can be used to pass user-defined data in and out of callback functions.

    The data should be appropriately interpreted with ctypes by the user.
    """
    return lgfxd.gfxd_udata_get()

# ====================================================================
#   Execution
# ====================================================================

lgfxd.gfxd_udata_set.argtypes = None
lgfxd.gfxd_udata_set.restype = c_int
def gfxd_execute() -> int:
    """
    Start executing gfxd with the current settings. For each macro, the macro handler registered with gfxd_macro_fn is called.

    Execution ends when the input ends, the macro handler returns non-zero, when an invalid macro is encountered and GfxdCap.stop_on_invalid is enabled,
    or when SPBranchList or SPEndDisplayList is encountered and gfxd_stop_on_end is enabled.
    If execution ends due to an invalid macro, -1 is returned.
    If execution ends because the macro handler returns non-zero, the return value from the macro handler is returned.
    Otherwise zero is returned.
    """
    return lgfxd.gfxd_execute()

# ====================================================================
#   Macro Information
# ====================================================================

lgfxd.gfxd_macro_offset.argtypes = None
lgfxd.gfxd_macro_offset.restype = c_int
def gfxd_macro_offset() -> int:
    """
    Returns the offset in the input data of the current macro.
    The offset starts at zero when gfxd_execute is called.
    """
    return lgfxd.gfxd_macro_offset()

lgfxd.gfxd_macro_packets.argtypes = None
lgfxd.gfxd_macro_packets.restype = c_int
def gfxd_macro_packets() -> int:
    """
    Returns the number of Gfx packets within the current macro.
    """
    return lgfxd.gfxd_macro_packets()

lgfxd.gfxd_macro_data.argtypes = None
lgfxd.gfxd_macro_data.restype = c_void_p
def gfxd_macro_data() -> bytearray:
    """
    Returns a bytearray object of the input data for the current macro.
    The data is not byte-swapped. The data has a length of 8 * gfxd_macro_packets().
    """
    lgfxd.gfxd_macro_data.restype = POINTER(c_ubyte * (8 * gfxd_macro_packets()))
    return bytearray(lgfxd.gfxd_macro_data().contents)

lgfxd.gfxd_macro_id.argtypes = None
lgfxd.gfxd_macro_id.restype = c_int
def gfxd_macro_id() -> GfxdMacroId:
    """
    Returns a number that uniquely identifies the current macro.
    """
    return GfxdMacroId(lgfxd.gfxd_macro_id())

lgfxd.gfxd_macro_name.argtypes = None
lgfxd.gfxd_macro_name.restype = c_char_p
def gfxd_macro_name() -> str:
    """
    Returns the name of the current macro. If the macro does not have a name (i.e. it's invalid), None is returned.

    If a dynamic display list pointer has been specified, the dynamic g version is returned.
    Otherwise the static gs version is returned.
    """
    return lgfxd.gfxd_macro_name().decode('utf-8')

lgfxd.gfxd_arg_count.argtypes = None
lgfxd.gfxd_arg_count.restype = c_int
def gfxd_arg_count() -> int:
    """
    Returns the number of arguments to the current macro, not including a dynamic display list pointer if one has been specified.
    """
    return lgfxd.gfxd_arg_count()

lgfxd.gfxd_arg_type.argtypes = [c_int]
lgfxd.gfxd_arg_type.restype = c_int
def gfxd_arg_type(arg_num: int) -> GfxdArgType:
    """
    Returns a number that identifies the type of the argument with index arg_num.
    """
    return GfxdArgType(lgfxd.gfxd_arg_type(arg_num))

lgfxd.gfxd_arg_name.argtypes = [c_int]
lgfxd.gfxd_arg_name.restype = c_char_p
def gfxd_arg_name(arg_num: int) -> str:
    """
    Returns the name of the argument with index arg_num. Argument names are not canonical,
    nor are they needed for macro disassembly, but they can be useful for informational and diagnostic purposes.
    """
    return lgfxd.gfxd_arg_name(arg_num).decode('utf-8')

lgfxd.gfxd_arg_fmt.argtypes = [c_int]
lgfxd.gfxd_arg_fmt.restype = c_int
def gfxd_arg_fmt(arg_num: int) -> GfxdArgfmt:
    """
    Returns the data format of the argument with index arg_num.

    The return value will be
        GfxdArgfmt.i for int32_t
        GfxdArgfmt.u for uint32_t
        GfxdArgfmt.f for float

    When accessing the value of the argument with gfxd_arg_value, the member with the corresponding type should be used.
    """
    return GfxdArgfmt(lgfxd.gfxd_arg_fmt(arg_num))

lgfxd.gfxd_arg_value.argtypes = [c_int]
lgfxd.gfxd_arg_value.restype = POINTER(c_int * 1)
def gfxd_arg_value(arg_num: int) -> Tuple[int, int, float]:
    """
    Returns a tuple of different representations of the argument value:
        (signed int, unsigned int, float)
    """
    raw = lgfxd.gfxd_arg_value(arg_num).contents[0]
    return uint_to_sint(raw), raw, uint_bits_to_float(raw)

lgfxd.gfxd_value_by_type.argtypes = None
lgfxd.gfxd_value_by_type.restype = POINTER(c_uint32 * 1)
def gfxd_value_by_type(type: GfxdArgType, idx: int) -> Tuple[int, int, float]:
    """
    Returns a tuple of different representations of the argument value:
        (signed int, unsigned int, float)
    """
    raw = lgfxd.gfxd_value_by_type(int(type), idx).contents[0]
    return uint_to_sint(raw), raw, uint_bits_to_float(raw)

lgfxd.gfxd_arg_valid.argtypes = [c_int]
lgfxd.gfxd_arg_valid.restype = c_int
def gfxd_arg_valid(arg_num: int) -> bool:
    """
    Returns non-zero if the argument with index arg_num is "valid", for some definition of valid.

    An invalid argument generally means that the disassembler found inconsistencies in the input data,
    or that the data can not be reproduced by the current macro type.

    The argument still has a value that can be printed, though the value is not guaranteed to make any sense.
    """
    return lgfxd.gfxd_arg_valid(arg_num) != 0

# ====================================================================
#   Custom Output
# ====================================================================

lgfxd.gfxd_write.argtypes = [c_void_p]
lgfxd.gfxd_write.restype = c_int
def gfxd_write(data: bytes) -> int:
    """
    Insert count bytes from the buffer at buf into the output.

    The number of characters written is returned.
    """
    buffer = create_string_buffer(data, len(data))
    __gfxd_buffers_callbacks.update({10001 : buffer})
    return lgfxd.gfxd_write(c_char_p(buffer), len(buffer))

lgfxd.gfxd_puts.argtypes = [c_char_p]
lgfxd.gfxd_puts.restype = c_int
def gfxd_puts(string: str) -> int:
    """
    Insert the string into the output.

    The number of characters written is returned.
    """
    return lgfxd.gfxd_puts(c_char_p(string.encode("utf-8")))

lgfxd.gfxd_printf.argtypes = [c_char_p]
lgfxd.gfxd_printf.restype = c_int
def gfxd_printf(string: str) -> int:
    """
    Insert the printf-formatted string described by fmt and additional
    arguments into the output. Limited to 255 characters.

    The number of characters written is returned.
    """
    if len(string) > 255:
        raise GfxdArgumentError("gfxd_printf: len(string) > 255", "gfxd_printf is limited to 255 characters")

    return lgfxd.gfxd_printf(c_char_p(string.encode("utf-8")))

lgfxd.gfxd_print_value.argtypes = [c_int, POINTER(c_int32)]
lgfxd.gfxd_print_value.restype = c_int
def gfxd_print_value(type: GfxdArgType, value: Tuple[int, int, float]) -> int:
    """
    Insert the type-formatted value into the output.

    The number of characters written is returned.

    The macro argument with index n can be printed with
        gfxd_print_value(gfxd_arg_type(n), gfxd_arg_value(n))
    """
    return lgfxd.gfxd_print_value(int(type), byref(c_int32(value[0])))

# ====================================================================
#   Python Utilities
# ====================================================================

def gfxd_buffer_to_string(buffer: c_void_p) -> str:
    """
    Primary purpose is to fetch the contents of the output buffer as a python string.
    """
    return buffer.value.decode('utf-8')
