use super::structs::PhysicalAddress;

cfg_if::cfg_if! {
    if #[cfg(not(test))] {
        use core::arch::{asm, global_asm};
        global_asm!(include_str!("replace_table_entry.asm"));
        // Use efiapi for the consistent calling convention.
        extern "efiapi" {
            pub(crate) fn replace_live_xlat_entry(entry_ptr: u64, val: u64, addr: u64);
        }
    }
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
    #[allow(unused_assignments)]
    let mut pa_bits: u64 = 0;

    #[cfg(not(test))]
    unsafe {
        asm!(
        "mrs {}, id_aa64mmfr0_el1",
        out(reg) pa_bits
        );
    }

    // Mask off the bits we care about
    pa_bits &= 0xf;

    if pa_bits > 7 {
        // Reserved value
        return 0;
    }

    // Convert the value to the number of bits
    (pa_bits << 2) + 32
}

pub(crate) fn get_current_el() -> u64 {
    // Default to EL2
    let mut _current_el: u64 = 8;
    #[cfg(not(test))]
    unsafe {
        asm!(
        "mrs {}, CurrentEL",
        out(reg) _current_el
        );
    }

    match _current_el {
        0x0C => 3,
        0x08 => 2,
        0x04 => 1,
        _ => panic!("Invalid current EL {}", _current_el),
    }
}

pub(crate) fn set_tcr(_tcr: u64) {
    #[cfg(not(test))]
    unsafe {
        let current_el = get_current_el();
        if current_el == 2 {
            asm!(
            "msr tcr_el2, {}",
            in(reg) _tcr
            );
        } else if current_el == 1 {
            asm!(
            "msr tcr_el1, {}",
            in(reg) _tcr
            );
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("isb", options(nostack));
    }
}

pub(crate) fn set_ttbr0(_ttbr0: u64) {
    #[cfg(not(test))]
    unsafe {
        let current_el = get_current_el();
        if current_el == 2 {
            asm!(
              "msr ttbr0_el2, {}",
              in(reg) _ttbr0
            );
        } else if current_el == 1 {
            asm!(
            "msr ttbr0_el1, {}",
            in(reg) _ttbr0
            );
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("isb", options(nostack));
    }
}

pub(crate) fn set_mair(_mair: u64) {
    #[cfg(not(test))]
    unsafe {
        let current_el = get_current_el();
        if current_el == 2 {
            asm!(
              "msr mair_el2, {}",
              in(reg) _mair
            );
        } else if current_el == 1 {
            asm!(
            "msr mair_el1, {}",
            in(reg) _mair
            );
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("isb", options(nostack));
    }
}

pub(crate) fn is_mmu_enabled() -> bool {
    let mut _sctlr: u64 = 0;
    #[cfg(not(test))]
    unsafe {
        match get_current_el() {
            2 => asm!("mrs {}, sctlr_el2", out(reg) _sctlr),
            1 => asm!("mrs {}, sctlr_el1", out(reg) _sctlr),
            invalid_el => panic!("Invalid current EL {}", invalid_el),
        }
    }

    _sctlr & 0x1 == 1
}

pub(crate) fn enable_mmu() {
    #[cfg(not(test))]
    unsafe {
        let current_el = get_current_el();
        if current_el == 2 {
            asm!(
                "mrs x0, sctlr_el2",
                "orr x0, x0, #0x1",
                "tlbi alle2",
                "dsb nsh",
                "isb",
                "msr sctlr_el2, x0",
                options(nostack)
            );
        } else if current_el == 1 {
            asm!(
                "mrs x0, sctlr_el1",
                "orr x0, x0, #0x1",
                "tlbi vmalle1",
                "dsb nsh",
                "isb",
                "msr sctlr_el1, x0",
                options(nostack)
            );
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("isb", options(nostack));
    }
}

pub(crate) fn set_stack_alignment_check(_enable: bool) {
    #[cfg(not(test))]
    unsafe {
        let current_el = get_current_el();
        if current_el == 2 {
            if _enable {
                asm!("mrs x0, sctlr_el2", "orr x0, x0, #8", "msr sctlr_el2, x0", options(nostack));
            } else {
                asm!("mrs x0, sctlr_el2", "bic x0, x0, #8", "msr sctlr_el2, x0", options(nostack));
            }
        } else if current_el == 1 {
            if _enable {
                asm!("mrs x0, sctlr_el1", "orr x0, x0, #8", "msr sctlr_el1, x0", options(nostack));
            } else {
                asm!("mrs x0, sctlr_el1", "bic x0, x0, #8", "msr sctlr_el1, x0", options(nostack));
            }
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("dsb sy", options(nostack));
        asm!("isb", options(nostack));
    }
}

pub(crate) fn set_alignment_check(_enable: bool) {
    #[cfg(not(test))]
    unsafe {
        let current_el = get_current_el();
        if current_el == 2 {
            if _enable {
                asm!("mrs x0, sctlr_el2", "orr x0, x0, #2", "msr sctlr_el2, x0", options(nostack));
            } else {
                asm!("mrs x0, sctlr_el2", "bic x0, x0, #2", "msr sctlr_el2, x0", options(nostack));
            }
        } else if current_el == 1 {
            if _enable {
                asm!("mrs x0, sctlr_el1", "orr x0, x0, #2", "msr sctlr_el1, x0", options(nostack));
            } else {
                asm!("mrs x0, sctlr_el1", "bic x0, x0, #2", "msr sctlr_el1, x0", options(nostack));
            }
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("dsb sy", options(nostack));
        asm!("isb", options(nostack));
    }
}

pub(crate) fn enable_instruction_cache() {
    #[cfg(not(test))]
    unsafe {
        let current_el = get_current_el();
        if current_el == 2 {
            asm!("mrs x0, sctlr_el2", "orr x0, x0, #0x1000", "msr sctlr_el2, x0", options(nostack));
        } else if current_el == 1 {
            asm!("mrs x0, sctlr_el1", "orr x0, x0, #0x1000", "msr sctlr_el1, x0", options(nostack));
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("dsb sy", options(nostack));
        asm!("isb", options(nostack));
    }
}

pub(crate) fn enable_data_cache() {
    #[cfg(not(test))]
    unsafe {
        let current_el = get_current_el();
        if current_el == 2 {
            asm!("mrs x0, sctlr_el2", "orr x0, x0, #0x4", "msr sctlr_el2, x0", options(nostack));
        } else if current_el == 1 {
            asm!("mrs x0, sctlr_el1", "orr x0, x0, #0x4", "msr sctlr_el1, x0", options(nostack));
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("dsb sy", options(nostack));
        asm!("isb", options(nostack));
    }
}

pub(crate) fn update_translation_table_entry(_translation_table_entry: u64, _mva: u64) {
    #[cfg(not(test))]
    unsafe {
        let current_el = get_current_el();
        let ls_mva = _mva << 12;
        let mut sctlr: u64;
        asm!("dsb     nshst", options(nostack));
        if current_el == 2 {
            asm!(
                "tlbi vae2, {}",
                "mrs {}, sctlr_el2",
                in(reg) ls_mva,
                out(reg) sctlr,
                options(nostack)
            );
        } else if current_el == 1 {
            asm!(
                "tlbi vaae1, {}",
                "mrs {}, sctlr_el1",
                in(reg) ls_mva,
                out(reg) sctlr,
                options(nostack)
            );
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        if sctlr & 1 == 0 {
            asm!(
                "dc ivac, {}",
                in(reg) _translation_table_entry,
                options(nostack)
            );
        }
        asm!("dsb nsh", options(nostack));
        asm!("isb", options(nostack));
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

    #[cfg(not(test))]
    unsafe {
        asm!("dsb sy", options(nostack));
    }
}

fn data_cache_line_len() -> u64 {
    #[cfg(not(test))]
    {
        let ctr_el0 = unsafe {
            let ctr_el0: u64;
            asm!("mrs {}, ctr_el0", out(reg) ctr_el0);
            ctr_el0
        };
        return 4 << ((ctr_el0 >> 16) & 0xf);
    }
    #[cfg(test)]
    {
        // For all other cases, return 64 bytes
        64_u64
    }
}

fn clean_data_entry_by_mva(_mva: u64) {
    #[cfg(not(test))]
    unsafe {
        asm!("dc cvac, {}", in(reg) _mva, options(nostack, preserves_flags));
    }
}

fn invalidate_data_cache_entry_by_mva(_mva: u64) {
    #[cfg(not(test))]
    unsafe {
        asm!("dc ivac, {}", in(reg) _mva, options(nostack, preserves_flags));
    }
}

fn clean_and_invalidate_data_entry_by_mva(_mva: u64) {
    #[cfg(not(test))]
    unsafe {
        asm!("dc civac, {}", in(reg) _mva, options(nostack, preserves_flags));
    }
}

// Helper function to check if this page table is active
pub(crate) fn is_this_page_table_active(page_table_base: PhysicalAddress) -> bool {
    // Check the TTBR0 register to see if this page table matches
    // our base
    let mut _ttbr0: u64 = 0;
    let _current_el = get_current_el();
    #[cfg(not(test))]
    unsafe {
        match _current_el {
            2 => asm!("mrs {}, ttbr0_el2", out(reg) _ttbr0),
            1 => asm!("mrs {}, ttbr0_el1", out(reg) _ttbr0),
            invalid_el => panic!("Invalid current EL {}", invalid_el),
        }
    }

    if _ttbr0 != u64::from(page_table_base) {
        false
    } else {
        // Check to see if MMU is enabled
        #[cfg(not(test))]
        unsafe {
            let sctlr: u64;
            match _current_el {
                2 => asm!("mrs {}, sctlr_el2", out(reg) sctlr),
                1 => asm!("mrs {}, sctlr_el1", out(reg) sctlr),
                invalid_el => panic!("Invalid current EL {}", invalid_el),
            }
            return sctlr & 0x1 == 1;
        }
        #[allow(unreachable_code)]
        false
    }
}

/// Zero a page of memory
/// This is done in asm to:
/// 1. Ensure that the compiler does not optimize out the zeroing
/// 2. Ensure that the zeroing is done as quickly as possible as without this, the zero takes a long time on
///    non-optimized builds
///
/// # Safety
/// This function is unsafe because it operates on raw pointers. It requires the caller to ensure the VA passed in
/// is mapped.
pub(crate) unsafe fn zero_page(_page: u64) {
    #[cfg(not(test))]
    asm!(
        "mov x0, {}",               // Address of the page
        "mov x1, #0",               // Zero value
        "mov x2, #256",             // 256 iterations of 16 bytes each
        "1:",
        "stp x1, x1, [x0], #16",    // Store 0 to the next 16 bytes of the page
        "subs x2, x2, #1",          // Decrement the counter
        "bne 1b",                   // Loop back if we haven't done 256 iterations
        in(reg) _page,
        options(nostack, preserves_flags)
    );
}
