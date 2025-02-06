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

  # write invalid entry
  dsb   sy
  str   xzr, [x0]
  dsb   sy

  # flush translations for the target address from the TLBs
  lsr   x2, x2, #12
  tlbi  vae2, x2
  dsb   sy

  # write updated entry
  str   x1, [x0]
  dsb   sy
  isb

  msr   daif, x4
  ret

replace_live_xlat_entry_size:
  .long   . - replace_live_xlat_entry

  # Double check that we did not overrun the assumed maximum size or cross a
  # 0x200 boundary (and thus implicitly not any larger power of two, including
  # the page size).
  .align  9
  .org    replace_live_xlat_entry + 0x200
