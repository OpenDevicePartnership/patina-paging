# Implements assembly routines for installing page tables.
#
# Copyright (c) Microsoft Corporation.
#
# SPDX-License-Identifier: Apache-2.0
#

.global install_new_page_tables
.global install_new_page_tables_size

# fn install_new_page_tables(ttbr0: u64, tcr: u64, mair: u64);
#
# Installs a new page table. Disables the MMU and data cache, updates
# TCR, MAIR, TTBR0, invalidates the TLB, then sets SCTLR with:
#   M  = 1 (MMU enabled)
#   C  = 1 (data cache enabled)
#   I  = 1 (instruction cache enabled)
#   SA = 1 (stack alignment check enabled)
#   A  = 0 (alignment check disabled)
#
# Arguments:
#   x0 - TTBR0 value (page table base address)
#   x1 - TCR value (fully computed by caller, EL-specific)
#   x2 - MAIR value
#

.section .text.install_new_page_tables,"ax";
.balign 64;

install_new_page_tables:
    # Save and disable interrupts.
    mrs     x4, daif
    msr     daifset, #0xf
    isb

    # Detect exception level: CurrentEL bits [3:2].
    # EL2 = 0x8, EL1 = 0x4.
    mrs     x5, CurrentEL
    cmp     x5, #0x08
    b.eq    .Lel2_path

    # The caller should have already ensured this is either
    # EL1 or EL2 before calling. If not EL2 then it is EL1.

    # ---------------------------------------------------------------
    # EL1 path
    # ---------------------------------------------------------------

    # Disable MMU and data cache.
    mrs     x6, sctlr_el1
    bic     x6, x6, #0x1           // Clear M (bit 0)
    bic     x6, x6, #0x4           // Clear C (bit 2)
    msr     sctlr_el1, x6
    dsb     nsh
    isb

    # Set TCR
    msr     tcr_el1, x1

    # Set MAIR
    msr     mair_el1, x2

    # Set TTBR0
    msr     ttbr0_el1, x0
    dsb     nsh
    isb

    # Invalidate TLB
    tlbi    vmalle1
    dsb     nsh
    isb

    # Re-enable the MMU with all expected features.
    mrs     x6, sctlr_el1
    bic     x6, x6, #0x2           // Clear A  (alignment check off)
    orr     x6, x6, #0x1           // Set   M  (MMU enable)
    orr     x6, x6, #0x4           // Set   C  (data cache)
    orr     x6, x6, #0x8           // Set   SA (stack alignment check)
    orr     x6, x6, #0x1000        // Set   I  (instruction cache)
    msr     sctlr_el1, x6
    dsb     nsh
    isb

    b       .Lrestore_interrupts

    # ---------------------------------------------------------------
    # EL2 path
    # ---------------------------------------------------------------
.Lel2_path:
    # Disable MMU and data cache.
    mrs     x6, sctlr_el2
    bic     x6, x6, #0x1           // Clear M (bit 0)
    bic     x6, x6, #0x4           // Clear C (bit 2)
    msr     sctlr_el2, x6
    dsb     nsh
    isb

    # Set TCR
    msr     tcr_el2, x1

    # Set MAIR
    msr     mair_el2, x2

    # Set TTBR0
    msr     ttbr0_el2, x0
    dsb     nsh
    isb

    # Invalidate TLB
    tlbi    alle2
    dsb     nsh
    isb

    # Re-enable the MMU with all expected features.
    mrs     x6, sctlr_el2
    bic     x6, x6, #0x2           // Clear A  (alignment check off)
    orr     x6, x6, #0x1           // Set   M  (MMU enable)
    orr     x6, x6, #0x4           // Set   C  (data cache)
    orr     x6, x6, #0x8           // Set   SA (stack alignment check)
    orr     x6, x6, #0x1000        // Set   I  (instruction cache)
    msr     sctlr_el2, x6
    dsb     nsh
    isb

.Lrestore_interrupts:
    # Restore interrupt state and return.
    msr     daif, x4
    ret

install_new_page_tables_size:
    .long   . - install_new_page_tables

