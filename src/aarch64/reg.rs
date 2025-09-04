//! AArch64 system register and cache management utilities for page table and MMU control.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use core::ptr;
use core::sync::atomic::{Ordering, compiler_fence};

use crate::structs::{PAGE_SIZE, PhysicalAddress};

/// SCTLR Bit 0 (M) indicates stage 1 address translation is enabled.
const SCTLR_M_ENABLE: u64 = 0x1;

/// This crate only support AArch64 exception levels EL1 and EL2.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ExceptionLevel {
    EL1,
    EL2,
}

/// This enum is used to specify the type of barrier to use when writing to a system register and in which order.
enum BarrierType {
    Instruction,
    DataInstruction,
}

cfg_if::cfg_if! {
    if #[cfg(all(not(test), target_arch = "aarch64"))] {
        use core::arch::{asm, global_asm};
        global_asm!(include_str!("replace_table_entry.asm"));
        // Use efiapi for the consistent calling convention.
        unsafe extern "efiapi" {
            pub(crate) fn replace_live_xlat_entry(entry_ptr: u64, val: u64, addr: u64);
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

macro_rules! write_sysreg {
  ($reg:expr, $value:expr) => {{
    // no barrier required case
    let _value: u64 = $value;
    let _ = $reg; // Helps prevent identical code being generated in tests.
    #[cfg(all(not(test), target_arch = "aarch64"))]
    // SAFETY: inline asm is inherently unsafe because Rust can't reason about it. In this case we are writing to a
    // system register, which is a safe operation as long as the caller ensures that the value being written is valid
    // for that register.
    unsafe {
      asm!(concat!("msr ", $reg, ", {}"), in(reg) _value, options(nostack, preserves_flags));
    }
  }};
  ($reg:expr, $value:expr, $barrier:expr) => {{
    // barrier required case
    let _value: u64 = $value;
    let _ = $reg; // Helps prevent identical code being generated in tests.
    let _barrier: BarrierType = $barrier;
    #[cfg(all(not(test), target_arch = "aarch64"))]
    match _barrier {
      // SAFETY: inline asm is inherently unsafe because Rust can't reason about it. In this case we are writing to a
      // system register, which is a safe operation as long as the caller ensures that the value being written is valid
      // for that register.
      BarrierType::Instruction => unsafe {
        asm!(concat!("msr ", $reg, ", {}"), "isb sy", in(reg) _value, options(nostack, preserves_flags));
      },
      // SAFETY: inline asm is inherently unsafe because Rust can't reason about it. In this case we are writing to a
      // system register, which is a safe operation as long as the caller ensures that the value being written is valid
      // for that register.
      BarrierType::DataInstruction => unsafe {
        asm!(concat!("msr ", $reg, ", {}"), "dsb sy", "isb sy", in(reg) _value, options(nostack, preserves_flags));
      }
    }
  }};
}

pub(crate) enum CpuFlushType {
    _EfiCpuFlushTypeWriteBackInvalidate,
    _EfiCpuFlushTypeWriteBack,
    EFiCpuFlushTypeInvalidate,
}

pub(crate) fn get_phys_addr_bits() -> u64 {
    // read the id_aa64mmfr0_el1 register to get the physical address bits
    // Bits 0..3 of the id_aa64mmfr0_el1 system register encode the size of the
    // physical address space support on this CPU:
    // 0 == 32 bits, 1 == 36 bits, etc etc
    // 7 and up are reserved
    //
    // The value is encoded as 2^(n+1) where n is the number of bits
    // supported. So 0b0000 == 2^32 == 4GB, 0b0001 == 2^36 == 8GB, etc
    let mut pa_bits = read_sysreg!("id_aa64mmfr0_el1", 0);

    // Mask off the bits we care about
    pa_bits &= 0xf;

    if pa_bits > 7 {
        // Reserved value
        return 0;
    }

    // Convert the value to the number of bits
    (pa_bits << 2) + 32
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

pub(crate) fn set_tcr(tcr: u64) {
    match get_current_el() {
        ExceptionLevel::EL2 => write_sysreg!("tcr_el2", tcr, BarrierType::Instruction),
        ExceptionLevel::EL1 => write_sysreg!("tcr_el1", tcr, BarrierType::Instruction),
    }
}

pub(crate) fn set_ttbr0(ttbr0: u64) {
    match get_current_el() {
        ExceptionLevel::EL2 => write_sysreg!("ttbr0_el2", ttbr0, BarrierType::Instruction),
        ExceptionLevel::EL1 => write_sysreg!("ttbr0_el1", ttbr0, BarrierType::Instruction),
    }

    // Invalidate the TLB after setting TTBR0
    invalidate_tlb();
}

pub(crate) fn set_mair(mair: u64) {
    match get_current_el() {
        ExceptionLevel::EL2 => write_sysreg!("mair_el2", mair, BarrierType::Instruction),
        ExceptionLevel::EL1 => write_sysreg!("mair_el1", mair, BarrierType::Instruction),
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

pub(crate) fn enable_mmu() {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    // SAFETY: inline asm is inherently unsafe because Rust can't reason about it.
    // In this case we are enabling the MMU, which is a safe operation as long as the caller ensures
    // that the page tables are properly set up.
    unsafe {
        match get_current_el() {
            ExceptionLevel::EL2 => {
                asm!(
                    "mrs {val}, sctlr_el2",
                    "orr {val}, {val}, #0x1",
                    "tlbi alle2",
                    "dsb nsh",
                    "isb sy",
                    "msr sctlr_el2, {val}",
                    "isb sy",
                    val = out(reg) _,
                    options(nostack)
                );
            }
            ExceptionLevel::EL1 => {
                asm!(
                    "mrs {val}, sctlr_el1",
                    "orr {val}, {val}, #0x1",
                    "tlbi vmalle1",
                    "dsb nsh",
                    "isb sy",
                    "msr sctlr_el1, {val}",
                    "isb sy",
                    val = out(reg) _,
                    options(nostack)
                );
            }
        }
    }
}

pub(crate) fn set_stack_alignment_check(enable: bool) {
    match get_current_el() {
        ExceptionLevel::EL2 => {
            let sctlr = read_sysreg!("sctlr_el2", 0);
            match enable {
                true => write_sysreg!("sctlr_el2", sctlr | 0x8, BarrierType::DataInstruction),
                false => write_sysreg!("sctlr_el2", sctlr & !0x8, BarrierType::DataInstruction),
            }
        }
        ExceptionLevel::EL1 => {
            let sctlr = read_sysreg!("sctlr_el1", 0);
            match enable {
                true => write_sysreg!("sctlr_el1", sctlr | 0x8, BarrierType::DataInstruction),
                false => write_sysreg!("sctlr_el1", sctlr & !0x8, BarrierType::DataInstruction),
            }
        }
    }
}

pub(crate) fn set_alignment_check(enable: bool) {
    match get_current_el() {
        ExceptionLevel::EL2 => {
            let sctlr = read_sysreg!("sctlr_el2", 0);
            match enable {
                true => write_sysreg!("sctlr_el2", sctlr | 0x2, BarrierType::DataInstruction),
                false => write_sysreg!("sctlr_el2", sctlr & !0x2, BarrierType::DataInstruction),
            }
        }
        ExceptionLevel::EL1 => {
            let sctlr = read_sysreg!("sctlr_el1", 0);
            match enable {
                true => write_sysreg!("sctlr_el1", sctlr | 0x2, BarrierType::DataInstruction),
                false => write_sysreg!("sctlr_el1", sctlr & !0x2, BarrierType::DataInstruction),
            }
        }
    }
}

pub(crate) fn enable_instruction_cache() {
    match get_current_el() {
        ExceptionLevel::EL2 => {
            let sctlr = read_sysreg!("sctlr_el2", 0);
            write_sysreg!("sctlr_el2", sctlr | 0x1000, BarrierType::DataInstruction);
        }
        ExceptionLevel::EL1 => {
            let sctlr = read_sysreg!("sctlr_el1", 0);
            write_sysreg!("sctlr_el1", sctlr | 0x1000, BarrierType::DataInstruction);
        }
    }
}

pub(crate) fn enable_data_cache() {
    match get_current_el() {
        ExceptionLevel::EL2 => {
            let sctlr = read_sysreg!("sctlr_el2", 0);
            write_sysreg!("sctlr_el2", sctlr | 0x4, BarrierType::DataInstruction);
        }
        ExceptionLevel::EL1 => {
            let sctlr = read_sysreg!("sctlr_el1", 0);
            write_sysreg!("sctlr_el1", sctlr | 0x4, BarrierType::DataInstruction);
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
