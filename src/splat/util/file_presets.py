"""
Utilities to write assembly-related macros.
This includes writing files like:
- include/include_asm.h
- include/macro.inc
- include/labels.inc
- include/gte_macros.inc

The directory where these files are written to can be controlled with
`options.opts.generated_asm_macros_directory`.
"""

from pathlib import Path

from . import options, log


def write_all_files():
    if not options.opts.generate_asm_macros_files:
        return

    write_include_asm_h()
    write_assembly_inc_files()


def _write(filepath: str, contents: str):
    p = Path(filepath)
    p.parent.mkdir(parents=True, exist_ok=True)

    if p.exists():
        with p.open("r", encoding="UTF-8") as f:
            existing_contents = f.read()
        if existing_contents == contents:
            return
    with p.open("w", encoding="UTF-8", newline="\n") as f:
        f.write(contents)


def write_include_asm_h():
    if not options.opts.compiler.uses_include_asm:
        # These compilers do not use the `INCLUDE_ASM` macro.
        return

    directory = options.opts.generated_asm_macros_directory.as_posix()

    if options.opts.include_asm_macro_style == "maspsx_hack":
        include_asm_macro = """\
#define INCLUDE_ASM(FOLDER, NAME) \\
    void __maspsx_include_asm_hack_##NAME() { \\
        __asm__( \\
            ".text # maspsx-keep \\n" \\
            "    .align 2 # maspsx-keep\\n" \\
            "    .set noat # maspsx-keep\\n" \\
            "    .set noreorder # maspsx-keep\\n" \\
            "    .include \\"" FOLDER "/" #NAME ".s\\" # maspsx-keep\\n" \\
            "    .set reorder # maspsx-keep\\n" \\
            "    .set at # maspsx-keep\\n" \\
        ); \\
    }
"""
    else:  # default
        include_asm_macro = """\
#define INCLUDE_ASM(FOLDER, NAME) \\
    __asm__( \\
        ".section .text\\n" \\
        "    .set noat\\n" \\
        "    .set noreorder\\n" \\
        "    .include \\"" FOLDER "/" #NAME ".s\\"\\n" \\
        "    .set reorder\\n" \\
        "    .set at\\n" \\
    )
"""

    include_rodata_macro = """\
#define INCLUDE_RODATA(FOLDER, NAME) \\
    __asm__( \\
        ".section .rodata\\n" \\
        "    .include \\"" FOLDER "/" #NAME ".s\\"\\n" \\
        ".section .text" \\
    )
"""

    file_data = f"""\
#ifndef INCLUDE_ASM_H
#define INCLUDE_ASM_H

#if !defined(M2CTX) && !defined(PERMUTER)

#ifndef INCLUDE_ASM
{include_asm_macro}\
#endif
#ifndef INCLUDE_RODATA
{include_rodata_macro}\
#endif

#if INCLUDE_ASM_USE_MACRO_INC
__asm__(".include \\"{directory}/macro.inc\\"\\n");
#else
__asm__(".include \\"{directory}/labels.inc\\"\\n");
#endif

#else

#ifndef INCLUDE_ASM
#define INCLUDE_ASM(FOLDER, NAME)
#endif
#ifndef INCLUDE_RODATA
#define INCLUDE_RODATA(FOLDER, NAME)
#endif

#endif /* !defined(M2CTX) && !defined(PERMUTER) */

#endif /* INCLUDE_ASM_H */
"""
    _write(f"{directory}/include_asm.h", file_data)


def write_assembly_inc_files():
    directory = options.opts.generated_asm_macros_directory.as_posix()

    func_macros = f"""\
# A function symbol.
.macro {options.opts.asm_function_macro} label, visibility=global
    .\\visibility \\label
    .type \\label, @function
    \\label:
        .ent \\label
.endm
"""
    if options.opts.asm_end_label != "":
        func_macros += f"""
# The end of a function symbol.
.macro {options.opts.asm_end_label} label
    .size \\label, . - \\label
    .end \\label
.endm
"""
    if (
        options.opts.asm_function_alt_macro != ""
        and options.opts.asm_function_alt_macro != options.opts.asm_function_macro
    ):
        func_macros += f"""
# An alternative entry to a function.
.macro {options.opts.asm_function_alt_macro} label, visibility=global
    .\\visibility \\label
    .type \\label, @function
    \\label:
        .aent \\label
.endm
"""
    if (
        options.opts.asm_ehtable_label_macro != ""
        and options.opts.asm_ehtable_label_macro != options.opts.asm_function_macro
    ):
        func_macros += f"""
# A label referenced by an error handler table.
.macro {options.opts.asm_ehtable_label_macro} label, visibility=global
    .\\visibility \\label
    \\label:
.endm
"""

    jlabel_macro_labelsinc = ""
    jlabel_macro_macroinc = ""
    if (
        options.opts.asm_jtbl_label_macro != ""
        and options.opts.asm_jtbl_label_macro != options.opts.asm_function_macro
    ):
        jlabel_macro_macroinc = f"""
# A label referenced by a jumptable.
.macro {options.opts.asm_jtbl_label_macro} label, visibility=global
    .\\visibility \\label
    \\label:
.endm
"""
        if options.opts.migrate_rodata_to_functions:
            jlabel_macro_labelsinc = f"""
# A label referenced by a jumptable.
.macro {options.opts.asm_jtbl_label_macro} label, visibility=local
    .\\visibility \\label
    \\label:
.endm
"""
        else:
            # If the user doesn't migrate rodata, like jumptables, to functions
            # then the user will need jlabels to be global instead of local,
            # so we just reuse the definition from macro.inc
            jlabel_macro_labelsinc = jlabel_macro_macroinc

    data_macros = ""
    if (
        options.opts.asm_data_macro != ""
        and options.opts.asm_data_macro != options.opts.asm_function_macro
    ):
        data_macros += f"""
# A data symbol.
.macro {options.opts.asm_data_macro} label, visibility=global
    .\\visibility \\label
    .type \\label, @object
    \\label:
.endm
"""
    if options.opts.asm_data_end_label != "":
        data_macros += f"""
# End of a data symbol.
.macro {options.opts.asm_data_end_label} label
    .size \\label, . - \\label
.endm
"""

    nm_macros = ""
    if options.opts.asm_nonmatching_label_macro != "":
        nm_macros = f"""
# Label to signal the symbol haven't been matched yet.
.macro {options.opts.asm_nonmatching_label_macro} label, size=1
    .global \\label\\().NON_MATCHING
    .type \\label\\().NON_MATCHING, @object
    .size \\label\\().NON_MATCHING, \\size
    \\label\\().NON_MATCHING:
.endm
"""

    macros_inc = f"""\
{func_macros}
{jlabel_macro_macroinc}
{data_macros}
{nm_macros}\
"""

    if options.opts.compiler.uses_include_asm:
        # File used by original assembler
        preamble = "# This file is used by the original compiler/assembler.\n# Defines the expected assembly macros.\n"

        if options.opts.platform == "psx":
            preamble += '\n.include "gte_macros.inc"\n'

        labels_inc = f"""\
{preamble}
{func_macros}
{jlabel_macro_labelsinc}
{data_macros}
{nm_macros}\
"""
        _write(f"{directory}/labels.inc", labels_inc)

    if options.opts.platform in {"n64", "psx"}:
        gas = macros_inc
    elif options.opts.platform in {"ps2", "psp"}:
        # ps2 and psp usually use c++ mangled names, so we need to quote those
        # names when using modern gas to avoid build errors.
        # This means we can't reuse the labels.inc file.
        gas = macros_inc.replace("\\label", '"\\label"').replace(
            '"\\label"\\().NON_MATCHING', '"\\label\\().NON_MATCHING"'
        )
    elif not options.opts.is_unsupported_platform:
        log.error(f"Unknown platform '{options.opts.platform}'")
    else:
        gas = macros_inc

    if options.opts.platform == "n64":
        gas += """
# COP0 register aliases

.set Index,         $0
.set Random,        $1
.set EntryLo0,      $2
.set EntryLo1,      $3
.set Context,       $4
.set PageMask,      $5
.set Wired,         $6
.set Reserved07,    $7
.set BadVaddr,      $8
.set Count,         $9
.set EntryHi,       $10
.set Compare,       $11
.set Status,        $12
.set Cause,         $13
.set EPC,           $14
.set PRevID,        $15
.set Config,        $16
.set LLAddr,        $17
.set WatchLo,       $18
.set WatchHi,       $19
.set XContext,      $20
.set Reserved21,    $21
.set Reserved22,    $22
.set Reserved23,    $23
.set Reserved24,    $24
.set Reserved25,    $25
.set PErr,          $26
.set CacheErr,      $27
.set TagLo,         $28
.set TagHi,         $29
.set ErrorEPC,      $30
.set Reserved31,    $31

# Float register aliases

.set $fv0,          $f0
.set $fv0f,         $f1
.set $fv1,          $f2
.set $fv1f,         $f3
.set $ft0,          $f4
.set $ft0f,         $f5
.set $ft1,          $f6
.set $ft1f,         $f7
.set $ft2,          $f8
.set $ft2f,         $f9
.set $ft3,          $f10
.set $ft3f,         $f11
.set $fa0,          $f12
.set $fa0f,         $f13
.set $fa1,          $f14
.set $fa1f,         $f15
.set $ft4,          $f16
.set $ft4f,         $f17
.set $ft5,          $f18
.set $ft5f,         $f19
.set $fs0,          $f20
.set $fs0f,         $f21
.set $fs1,          $f22
.set $fs1f,         $f23
.set $fs2,          $f24
.set $fs2f,         $f25
.set $fs3,          $f26
.set $fs3f,         $f27
.set $fs4,          $f28
.set $fs4f,         $f29
.set $fs5,          $f30
.set $fs5f,         $f31
"""
    elif options.opts.platform == "psx":
        gas += '\n.include "gte_macros.inc"\n'
        write_gte_macros()

    if options.opts.generated_macro_inc_content is not None:
        gas += f"\n{options.opts.generated_macro_inc_content}\n"

    # File used by modern gas
    preamble = (
        "# This file is used by modern gas.\n# Defines the expected assembly macros\n"
    )
    gas = f"""\
# Evaluate this file only once in case it's included more than once
.ifndef _MACRO_INC_GUARD
.internal _MACRO_INC_GUARD
.set _MACRO_INC_GUARD, 1

{gas}
.endif
"""
    _write(f"{directory}/macro.inc", f"{preamble}\n{gas}")


def write_gte_macros():
    # Taken directly from https://github.com/Decompollaborate/rabbitizer/blob/-/docs/r3000gte/gte_macros.s
    # Please try to upstream any fix/update done here.
    gte_macros = """\
.ifndef .L_GTE_MACRO_INC
.L_GTE_MACRO_INC:

## GTE instruction macros
## These are meant for use with GAS and replace DMPSX

.macro cop2op fake_op, op, gbg = 0, sf = 1, mx = 0, v = 0, cv = 0, lm = 0
    cop2 \\fake_op << 20 | \\gbg << 20 | \\sf << 19 | \\mx << 17 | \\v << 15 | \\cv << 13 | \\lm << 10 | \\op
.endm

/*  RTPS    15      0x4A180001  Perspective transform */
.macro rtps
    cop2op 0x01, 0x01
.endm

/*  RTPT    23      0x4A280030  Perspective transform on 3 points */
.macro rtpt
    cop2op 0x02, 0x30
.endm

/*  DPCL    8       0x4A680029  Depth Cue Color light */
.macro dpcl
    cop2op 0x06, 0x29
.endm

/*  DPCS    8       0x4A780010  Depth Cueing */
.macro dpcs
    cop2op 0x07, 0x10
.endm

/*  DPCT    17      0x4AF8002A  Depth cue color RGB0,RGB1,RGB2 */
.macro dpct
    cop2op 0x0F, 0x2A
.endm

/*  INTPL   8       0x4A980011  Interpolation of vector and far color */
.macro intpl
    cop2op 0x09, 0x11
.endm

/*  NCS     14      0x4AC8041E  Normal color v0 */
.macro ncs
    cop2op 0x0C, 0x1E, lm = 1
.endm

/*  NCT     30      0x4AD80420  Normal color v0, v1, v2 */
.macro nct
    cop2op 0x0D, 0x20, lm = 1
.endm

/*  NCDS    19      0x4AE80413  Normal color depth cuev0 */
.macro ncds
    cop2op 0x0E, 0x13, lm = 1
.endm

/*  NCDT    44      0x4AF80416  Normal color depth cue v0, v1, v2 */
.macro ncdt
    cop2op 0x0F, 0x16, lm = 1
.endm

/*  NCCS    17      0x4B08041B  Normal color col. v0 */
.macro nccs
    cop2op 0x10, 0x1B, lm = 1
.endm

/*  NCCT    39      0x4B18043F  Normal color col.v0, v1, v2 */
.macro ncct
    cop2op 0x11, 0x3F, lm = 1
.endm

/*  CDP     13      0x4B280414  Color Depth Queue */
.macro cdp
    cop2op 0x12, 0x14, lm = 1
.endm

/*  CC      11      0x4B38041C  Color Col. */
.macro cc
    cop2op 0x13, 0x1C, lm = 1
.endm

/*  NCLIP   8       0x4B400006  Normal clipping */
.macro nclip
    cop2op 0x14, 0x06, sf = 0
.endm

/*  AVSZ3   5       0x4B58002D  Average of three Z values */
.macro avsz3
    cop2op 0x15, 0x2D
.endm

/*  AVSZ4   6       0x4B68002E  Average of four Z values */
.macro avsz4
    cop2op 0x16, 0x2E
.endm


## Instructions which take an argument
# gbg: arg is 5 bit wide
# sf : arg is 1 bit wide
# mx : arg is 2 bit wide
# v  : arg is 2 bit wide
# cv : arg is 2 bit wide
# lm : arg is 1 bit wide

/*  mvmva   8       0x4A4nnn12  Multiply vector by matrix and vector addition. */
.macro mvmva sf, mx, v, cv, lm
    cop2op 0x04, 0x12, sf = \\sf, mx = \\mx, v = \\v, cv = \\cv, lm = \\lm
.endm

/*  SQR     5       0x4AAn0428  Square of vector */
.macro sqr sf
    cop2op 0x0A, 0x28, sf = \\sf, lm = 1
.endm

/*  OP      6       0x4B7n000C  Outer Product */
.macro op sf
    cop2op 0x17, 0x0C, sf = \\sf
.endm

/*  GPF     6       0x4B9n003D  General purpose interpolation */
.macro gpf sf
    cop2op 0x19, 0x3D, sf = \\sf
.endm

/*  GPL     5       0x4BAn003E  general purpose interpolation */
.macro gpl sf
    cop2op 0x1A, 0x3E, sf = \\sf
.endm


## Convenience macros

/*  rtv0    -       0x4A486012  v0 * rotmatrix */
.macro rtv0
    # .word 0x4A486012
    mvmva       1, 0, 0, 3, 0
.endm

/*  rtv1    -       0x4A48E012  v1 * rotmatrix */
.macro rtv1
    # .word 0x4A48E012
    mvmva       1, 0, 1, 3, 0
.endm

/*  rtv2    -       0x4A496012  v2 * rotmatrix */
.macro rtv2
    # .word 0x4A496012
    mvmva       1, 0, 2, 3, 0
.endm

/*  rtir12  -       0x4A49E012  ir * rotmatrix */
.macro rtir12
    # .word 0x4A49E012
    mvmva       1, 0, 3, 3, 0
.endm

/*  rtir0   -       0x4A41E012  ir * rotmatrix */
.macro rtir0
    # .word 0x4A41E012
    mvmva       0, 0, 3, 3, 0
.endm

/*  rtv0tr  -       0x4A480012  v0 * rotmatrix + tr vector */
.macro rtv0tr
    # .word 0x4A480012
    mvmva       1, 0, 0, 0, 0
.endm

/*  rtv1tr  -       0x4A488012  v1 * rotmatrix + tr vector */
.macro rtv1tr
    # .word 0x4A488012
    mvmva       1, 0, 1, 0, 0
.endm

/*  rtv2tr  -       0x4A490012  v2 * rotmatrix + tr vector */
.macro rtv2tr
    # .word 0x4A490012
    mvmva       1, 0, 2, 0, 0
.endm

/*  rtirtr  -       0x4A498012  ir * rotmatrix + tr vector */
.macro rtirtr
    # .word 0x4A498012
    mvmva       1, 0, 3, 0, 0
.endm

/*  rtv0bk  -       0x4A482012  v0 * rotmatrix + bk vector */
.macro rtv0bk
    # .word 0x4A482012
    mvmva       1, 0, 0, 1, 0
.endm

/*  rtv1bk  -       0x4A48A012  v1 * rotmatrix + bk vector */
.macro rtv1bk
    # .word 0x4A48A012
    mvmva       1, 0, 1, 1, 0
.endm

/*  rtv2bk  -       0x4A492012  v2 * rotmatrix + bk vector */
.macro rtv2bk
    # .word 0x4A492012
    mvmva       1, 0, 2, 1, 0
.endm

/*  rtirbk  -       0x4A49A012  ir * rotmatrix + bk vector */
.macro rtirbk
    # .word 0x4A49A012
    mvmva       1, 0, 3, 1, 0
.endm

/*  ll      -       0x4A4A6412  v0 * light matrix. Lower limit result to 0 */
.macro ll
    # .word 0x4A4A6412
    mvmva       1, 1, 0, 3, 1
.endm

/*  llv0    -       0x4A4A6012  v0 * light matrix */
.macro llv0
    # .word 0x4A4A6012
    mvmva       1, 1, 0, 3, 0
.endm

/*  llv1    -       0x4A4AE012  v1 * light matrix */
.macro llv1
    # .word 0x4A4AE012
    mvmva       1, 1, 1, 3, 0
.endm

/*  llv2    -       0x4A4B6012  v2 * light matrix */
.macro llv2
    # .word 0x4A4B6012
    mvmva       1, 1, 2, 3, 0
.endm

/*  llvir   -       0x4A4BE012  ir * light matrix */
.macro llvir
    # .word 0x4A4BE012
    mvmva       1, 1, 3, 3, 0
.endm

/*  llv0tr  -       0x4A4A0012  v0 * light matrix + tr vector */
.macro llv0tr
    # .word 0x4A4A0012
    mvmva       1, 1, 0, 0, 0
.endm

/*  llv1tr  -       0x4A4A8012  v1 * light matrix + tr vector */
.macro llv1tr
    # .word 0x4A4A8012
    mvmva       1, 1, 1, 0, 0
.endm

/*  llv2tr  -       0x4A4B0012  v2 * light matrix + tr vector */
.macro llv2tr
    # .word 0x4A4B0012
    mvmva       1, 1, 2, 0, 0
.endm

/*  llirtr  -       0x4A4B8012  ir * light matrix + tr vector */
.macro llirtr
    # .word 0x4A4B8012
    mvmva       1, 1, 3, 0, 0
.endm

/*  llv0bk  -       0x4A4A2012  v0 * light matrix + bk vector */
.macro llv0bk
    # .word 0x4A4A2012
    mvmva       1, 1, 0, 1, 0
.endm

/*  llv1bk  -       0x4A4AA012  v1 * light matrix + bk vector */
.macro llv1bk
    # .word 0x4A4AA012
    mvmva       1, 1, 1, 1, 0
.endm

/*  llv2bk  -       0x4A4B2012  v2 * light matrix + bk vector */
.macro llv2bk
    # .word 0x4A4B2012
    mvmva       1, 1, 2, 1, 0
.endm

/*  llirbk  -       0x4A4BA012  ir * light matrix + bk vector */
.macro llirbk
    # .word 0x4A4BA012
    mvmva       1, 1, 3, 1, 0
.endm

/*  lc      -       0x4A4DA412  v0 * color matrix, Lower limit clamped to 0 */
.macro lc
    # .word 0x4A4DA412
    mvmva       1, 2, 3, 1, 1
.endm

/*  lcv0    -       0x4A4C6012  v0 * color matrix */
.macro lcv0
    # .word 0x4A4C6012
    mvmva       1, 2, 0, 3, 0
.endm

/*  lcv1    -       0x4A4CE012  v1 * color matrix */
.macro lcv1
    # .word 0x4A4CE012
    mvmva       1, 2, 1, 3, 0
.endm

/*  lcv2    -       0x4A4D6012  v2 * color matrix */
.macro lcv2
    # .word 0x4A4D6012
    mvmva       1, 2, 2, 3, 0
.endm

/*  lcvir   -       0x4A4DE012  ir * color matrix */
.macro lcvir
    # .word 0x4A4DE012
    mvmva       1, 2, 3, 3, 0
.endm

/*  lcv0tr  -       0x4A4C0012  v0 * color matrix + tr vector */
.macro lcv0tr
    # .word 0x4A4C0012
    mvmva       1, 2, 0, 0, 0
.endm

/*  lcv1tr  -       0x4A4C8012  v1 * color matrix + tr vector */
.macro lcv1tr
    # .word 0x4A4C8012
    mvmva       1, 2, 1, 0, 0
.endm

/*  lcv2tr  -       0x4A4D0012  v2 * color matrix + tr vector */
.macro lcv2tr
    # .word 0x4A4D0012
    mvmva       1, 2, 2, 0, 0
.endm

/*  lcirtr  -       0x4A4D8012  ir * color matrix + tr vector */
.macro lcirtr
    # .word 0x4A4D8012
    mvmva       1, 2, 3, 0, 0
.endm

/*  lev0bk  -       0x4A4C2012  v0 * color matrix + bk vector */
.macro lev0bk
    # .word 0x4A4C2012
    mvmva       1, 2, 0, 1, 0
.endm

/*  lev1bk  -       0x4A4CA012  v1 * color matrix + bk vector */
.macro lev1bk
    # .word 0x4A4CA012
    mvmva       1, 2, 1, 1, 0
.endm

/*  lev2bk  -       0x4A4D2012  v2 * color matrix + bk vector */
.macro lev2bk
    # .word 0x4A4D2012
    mvmva       1, 2, 2, 1, 0
.endm

/*  leirbk  -       0x4A4DA012  ir * color matrix + bk vector */
.macro leirbk
    # .word 0x4A4DA012
    mvmva       1, 2, 3, 1, 0
.endm

/*  sqr12   -       0x4AA80428  square of ir    1,19,12 */
# .macro sqr12
#     # .word 0x4AA80428
#     sqr         1
# .endm

/*  sqr0    -       0x4AA00428  square of ir    1,31, 0 */
# .macro sqr0
#     # .word 0x4AA00428
#     sqr         0
# .endm

/*  op12    -       0x4B78000C  outer product   1,19,12 */
.macro op12
    # .word 0x4B78000C
    op          1
.endm

/*  op0     -       0x4B70000C  outer product   1,31, 0 */
.macro op0
    # .word 0x4B70000C
    op          0
.endm

/*  gpf12   -       0x4B98003D  general purpose interpolation   1,19,12 */
.macro gpf12
    # .word 0x4B98003D
    gpf         1
.endm

/*  gpf0    -       0x4B90003D  general purpose interpolation   1,31, 0 */
.macro gpf0
    # .word 0x4B90003D
    gpf         0
.endm

/*  gpl12   -       0x4BA8003E  general purpose interpolation   1,19,12 */
.macro gpl12
    # .word 0x4BA8003E
    gpl         1
.endm

/*  gpl0    -       0x4BA0003E  general purpose interpolation   1,31, 0 */
.macro gpl0
    # .word 0x4BA0003E
    gpl         0
.endm

.endif
"""

    directory = options.opts.generated_asm_macros_directory.as_posix()
    _write(f"{directory}/gte_macros.inc", gte_macros)
