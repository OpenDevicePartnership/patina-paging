#------------------------------------------------------------------------------
#
# Copyright (c) 2016, Linaro Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
#------------------------------------------------------------------------------

  .section .text

.global replace_live_xlat_entry
.global replace_live_xlat_entry_size

  .set CTRL_M_BIT,      (1 << 0)

  .macro __replace_entry, el

.L1_\@:
  # write invalid entry
  str   xzr, [x0]
  dsb   nshst

  # flush translations for the target address from the TLBs
  lsr   x2, x2, #12
  .if   \el == 1
  tlbi  vaae1, x2
  .else
  tlbi  vae\el, x2
  .endif
  dsb   nsh

  # write updated entry
  str   x1, [x0]
  dsb   nshst
  isb

.L2_\@:
  .endm

# fn replace_live_xlat_entry(entry_ptr: u64, val: u64, addr: u64);
#
# Align this routine to a log2 upper bound of its size, so that it is
# guaranteed not to cross a page or block boundary.

  .section .text.replace_live_xlat_entry,"ax";
  .align 9;
  .org 0x0;

replace_live_xlat_entry:
  # disable interrupts
  mrs   x4, daif
  msr   daifset, #0xf
  isb

  mrs    x5, CurrentEL
  cmp    x5, #0x8
  b.gt   .
  b.eq   2f
  cbnz   x5, 1f
1:__replace_entry 1
  b     4f
2:__replace_entry 2
  b     4f
3:__replace_entry 3

4:msr   daif, x4
  ret

replace_live_xlat_entry_size:
  .long   . - replace_live_xlat_entry

  # Double check that we did not overrun the assumed maximum size or cross a
  # 0x200 boundary (and thus implicitly not any larger power of two, including
  # the page size).
  .align  9
  .org    replace_live_xlat_entry + 0x200
