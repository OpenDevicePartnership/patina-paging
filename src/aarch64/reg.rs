//! AArch64 system register and cache management utilities for page table and MMU control.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use core::{
    ptr,
    sync::atomic::{Ordering, compiler_fence},
};

use crate::structs::{PAGE_SIZE, PhysicalAddress};

/// SCTLR Bit 0 (M) indicates stage 1 address translation is enabled.
const SCTLR_M_ENABLE: u64 = 0x1;

/// This crate only support AArch64 exception levels EL1 and EL2.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ExceptionLevel {
    EL1,
    EL2,
}

cfg_if::cfg_if! {
    if #[cfg(all(not(test), target_arch = "aarch64"))] {
        use core::arch::{asm, global_asm};
        global_asm!(include_str!("replace_table_entry.asm"));
        global_asm!(include_str!("install_page_tables.asm"));
        // Use efiapi for the consistent calling convention.
        unsafe extern "efiapi" {
            pub(crate) fn replace_live_xlat_entry(entry_ptr: u64, val: u64, addr: u64);
            fn install_new_page_tables(ttbr0: u64, tcr: u64, mair: u64);
        }
        unsafe extern "C" {
            static install_new_page_tables_size: u32;
        }
    }
}

macro_rules! read_sysreg {
  ($reg:expr, $default:expr) => {{
    let mut _value: u64 = $default;
    let _ = $reg; // Helps prevent identical code being generated in tests.
    #[cfg(all(not(test), target_arch = "aarch64"))]
    // SAFETY: inline asm is inherently unsafe because Rust can't reason about it. In this case we are reading a
    // system register, which is a safe operation.
    unsafe {
      asm!(concat!("mrs {}, ", $reg), out(reg) _value, options(nostack, preserves_flags));
    }
    _value
  }};
}

pub(crate) enum CpuFlushType {
    _EfiCpuFlushTypeWriteBackInvalidate,
    _EfiCpuFlushTypeWriteBack,
    EFiCpuFlushTypeInvalidate,
}

#[coverage(off)] // Not be meaningfully tested without hardware support.
pub(crate) fn get_phys_addr_bits() -> u64 {
    // Read the ID_AA64MMFR0_EL1 register to get the physical address size.
    // Bits [3:0] (PARange) encode the supported physical address width.
    // The encoding is NOT uniform so a lookup table is required.
    let pa_range = read_sysreg!("id_aa64mmfr0_el1", 0) & 0xf;

    match pa_range {
        0 => 32,
        1 => 36,
        2 => 40,
        3 => 42,
        4 => 44,
        5 => 48,
        6 => 52,
        _ => 0, // Reserved
    }
}

/// Get the current exception level (EL) of the CPU
/// This crate only supports EL1 and EL2, so it will panic if the current EL is not one of those.
/// And only EL2 is tested :)
pub(crate) fn get_current_el() -> ExceptionLevel {
    // Default to EL2
    let current_el: u64 = read_sysreg!("CurrentEL", 8);

    match current_el {
        0x08 => ExceptionLevel::EL2,
        0x04 => ExceptionLevel::EL1,
        _ => unimplemented!("Unsupported exception level: {:#x}", current_el),
    }
}

#[coverage(off)] // This requires hardware for meaningful testing.
pub(crate) fn get_tcr() -> u64 {
    match get_current_el() {
        ExceptionLevel::EL2 => read_sysreg!("tcr_el2", 0),
        ExceptionLevel::EL1 => read_sysreg!("tcr_el1", 0),
    }
}

#[coverage(off)] // This requires hardware for meaningful testing.
pub(crate) fn get_ttbr0() -> u64 {
    match get_current_el() {
        ExceptionLevel::EL2 => read_sysreg!("ttbr0_el2", 0),
        ExceptionLevel::EL1 => read_sysreg!("ttbr0_el1", 0),
    }
}

pub(crate) fn is_mmu_enabled() -> bool {
    let sctlr: u64 = match get_current_el() {
        ExceptionLevel::EL2 => read_sysreg!("sctlr_el2", SCTLR_M_ENABLE),
        ExceptionLevel::EL1 => read_sysreg!("sctlr_el1", SCTLR_M_ENABLE),
    };

    sctlr & SCTLR_M_ENABLE == SCTLR_M_ENABLE
}

pub(crate) fn invalidate_tlb() {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    // SAFETY: inline asm is inherently unsafe because Rust can't reason about it.
    // In this case we are invalidating the TLB, which is a safe operation.
    unsafe {
        match get_current_el() {
            ExceptionLevel::EL2 => {
                asm!("tlbi alle2", "dsb nsh", "isb sy", options(nostack));
            }
            ExceptionLevel::EL1 => {
                asm!("tlbi alle1", "dsb nsh", "isb sy", options(nostack));
            }
        }
    }
}

pub(crate) fn update_translation_table_entry(_translation_table_entry: u64, _mva: u64) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    // SAFETY: inline asm is inherently unsafe because Rust can't reason about it. In this case we are updating a
    // translation table entry, which is a safe operation as long as the caller ensures that the entry being updated
    // is valid.
    unsafe {
        let pfn = _mva >> 12;
        let mut sctlr: u64;

        match get_current_el() {
            ExceptionLevel::EL2 => {
                asm!(
                    "dsb nshst",
                    "tlbi vae2, {}",
                    "mrs {}, sctlr_el2",
                    "dsb nsh",
                    "isb sy",
                    in(reg) pfn,
                    out(reg) sctlr,
                    options(nostack)
                );
            }
            ExceptionLevel::EL1 => {
                asm!(
                    "dsb nshst",
                    "tlbi vaae1, {}",
                    "mrs {}, sctlr_el1",
                    "dsb nsh",
                    "isb sy",
                    in(reg) pfn,
                    out(reg) sctlr,
                    options(nostack)
                );
            }
        }

        // If the MMU is disabled, we need to invalidate the cache
        if sctlr & 1 == 0 {
            asm!(
                "dc ivac, {}",
                "dsb nsh",
                "isb",
                in(reg) _translation_table_entry,
                options(nostack)
            );
        }
    }
}

// AArch64 related cache functions
pub(crate) fn cache_range_operation(start: u64, length: u64, op: CpuFlushType) {
    let cacheline_alignment = data_cache_line_len() - 1;
    let mut aligned_addr = start - (start & cacheline_alignment);
    let end_addr = start + length;

    loop {
        match op {
            CpuFlushType::_EfiCpuFlushTypeWriteBackInvalidate => clean_and_invalidate_data_entry_by_mva(aligned_addr),
            CpuFlushType::_EfiCpuFlushTypeWriteBack => clean_data_entry_by_mva(aligned_addr),
            CpuFlushType::EFiCpuFlushTypeInvalidate => invalidate_data_cache_entry_by_mva(aligned_addr),
        }

        aligned_addr += cacheline_alignment;
        if aligned_addr >= end_addr {
            break;
        }
    }

    // we have a data barrier after all cache lines have had the operation performed on them as an optimization
    // add the compiler fence to ensure that the compiler does not reorder memory accesses around this point
    compiler_fence(Ordering::SeqCst);
    #[cfg(all(not(test), target_arch = "aarch64"))]
    // SAFETY: inline asm is inherently unsafe because Rust can't reason about it.
    // In this case we are issuing a data barrier, which is a safe operation.
    unsafe {
        asm!("dsb sy", options(nostack, preserves_flags));
    }
}

fn data_cache_line_len() -> u64 {
    // Default to 64 bytes
    let ctr_el0 = read_sysreg!("ctr_el0", 0x1000000);
    4 << ((ctr_el0 >> 16) & 0xf)
}

fn clean_data_entry_by_mva(_mva: u64) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    // SAFETY: inline asm is inherently unsafe because Rust can't reason about it. In this case we are cleaning a
    // data cache entry, which is a safe operation as long as the caller ensures that the entry being cleaned is valid.
    unsafe {
        asm!("dc cvac, {}", in(reg) _mva, options(nostack, preserves_flags));
    }
}

fn invalidate_data_cache_entry_by_mva(_mva: u64) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    // SAFETY: inline asm is inherently unsafe because Rust can't reason about it. In this case we are invalidating a
    // data cache entry, which is a safe operation as long as the caller ensures that the entry being invalidated is
    // valid.
    unsafe {
        asm!("dc ivac, {}", in(reg) _mva, options(nostack, preserves_flags));
    }
}

fn clean_and_invalidate_data_entry_by_mva(_mva: u64) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    // SAFETY: inline asm is inherently unsafe because Rust can't reason about it. In this case we are cleaning and
    // invalidating a data cache entry, which is a safe operation as long as the caller ensures that the entry being
    // cleaned and invalidated is valid.
    unsafe {
        asm!("dc civac, {}", in(reg) _mva, options(nostack, preserves_flags));
    }
}

// Helper function to check if this page table is active
pub(crate) fn is_this_page_table_active(page_table_base: PhysicalAddress) -> bool {
    // Check the TTBR0 register to see if this page table matches
    // our base
    let mut _ttbr0: u64 = 0;
    let current_el = get_current_el();
    let ttbr0 = match current_el {
        ExceptionLevel::EL2 => read_sysreg!("ttbr0_el2", 0),
        ExceptionLevel::EL1 => read_sysreg!("ttbr0_el1", 0),
    };

    if ttbr0 != u64::from(page_table_base) {
        false
    } else {
        // Check to see if MMU is enabled
        is_mmu_enabled()
    }
}

/// Zero a page of memory
///
/// # Safety
/// This function is unsafe because it operates on raw pointers. It requires the caller to ensure the VA passed in
/// is mapped.
pub(crate) unsafe fn zero_page(page: u64) {
    // If the MMU is disabled, invalidate the cache so that any stale data does
    // not get later evicted to memory.
    if !is_mmu_enabled() {
        cache_range_operation(page, PAGE_SIZE, CpuFlushType::EFiCpuFlushTypeInvalidate);
    }

    // This cast must occur as a mutable pointer to a u8, as otherwise the compiler can optimize out the write,
    // which must not happen as that would violate break before make and have garbage in the page table.
    unsafe { ptr::write_bytes(page as *mut u8, 0, PAGE_SIZE as usize) };
}

/// Swaps the page table and related configuration registers.
///
/// ## Safety
///
/// The caller is responsible for ensuring that the provided TTBR0 is a valid address and the memory backing
/// the page tables has the appropriate lifetime to be installed in system registers.
#[coverage(off)]
pub(crate) unsafe fn swap_page_tables(_ttbr0: u64, _tcr: u64, _mair: u64) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    {
        // The assembly only supports EL1 & EL2. This compile-time check ensures
        // that addition of a new exception level causes a compilation failure here.
        const _: () = match ExceptionLevel::EL1 {
            ExceptionLevel::EL1 | ExceptionLevel::EL2 => (),
        };

        // The assembly disables the MMU. With the MMU disabled, the caching behavior
        // is not well defined. Make sure that the instructions required are written back
        // to avoid executing uninitialized memory under the cache.
        let asm_addr = install_new_page_tables as *const () as u64;
        // SAFETY: This is just accessing an assembly defined static, there is no contention or mutability issues with this.
        let asm_len = unsafe { install_new_page_tables_size } as u64;
        cache_range_operation(asm_addr, asm_len, CpuFlushType::_EfiCpuFlushTypeWriteBack);

        // SAFETY: The caller is responsible for ensuring a correct TTBR0 value.
        unsafe { install_new_page_tables(_ttbr0, _tcr, _mair) };
    }
}
