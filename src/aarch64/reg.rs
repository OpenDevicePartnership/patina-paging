use super::structs::PhysicalAddress;
#[allow(unused_imports)]
use core::arch::{asm, global_asm};

#[cfg(all(not(test), target_arch = "aarch64"))]
global_asm!(include_str!("replace_table_entry.asm"));

// Use efiapi for the consistent calling convention.
#[cfg(all(not(test), target_arch = "aarch64"))]
extern "efiapi" {
    pub fn replace_live_xlat_entry(entry_ptr: u64, val: u64, addr: u64);
}

use mu_pi::protocols::cpu_arch::CpuFlushType;

pub fn get_phys_addr_bits() -> u64 {
    // read the id_aa64mmfr0_el1 register to get the physical address bits
    // Bits 0..3 of the id_aa64mmfr0_el1 system register encode the size of the
    // physical address space support on this CPU:
    // 0 == 32 bits, 1 == 36 bits, etc etc
    // 7 and up are reserved
    //
    // The value is encoded as 2^(n+1) where n is the number of bits
    // supported. So 0b0000 == 2^32 == 4GB, 0b0001 == 2^36 == 8GB, etc
    let mut pa_bits: u64 = 0;

    #[cfg(all(not(test), target_arch = "aarch64"))]
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

pub fn get_current_el() -> u64 {
    // Default to EL2
    let mut _current_el: u64 = 8;
    #[cfg(all(not(test), target_arch = "aarch64"))]
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

pub fn set_tcr(_tcr: u64) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
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

pub fn set_ttbr0(_ttbr0: u64) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
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

pub fn set_mair(_mair: u64) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
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

pub fn is_mmu_enabled() -> bool {
    let mut _sctlr: u64 = 0;
    #[cfg(all(not(test), target_arch = "aarch64"))]
    unsafe {
        match get_current_el() {
            2 => asm!("mrs {}, sctlr_el2", out(reg) _sctlr),
            1 => asm!("mrs {}, sctlr_el1", out(reg) _sctlr),
            invalid_el => panic!("Invalid current EL {}", invalid_el),
        }
    }

    _sctlr & 0x1 == 1
}

pub fn enable_mmu() {
    #[cfg(all(not(test), target_arch = "aarch64"))]
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

pub fn set_stack_alignment_check(_enable: bool) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
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

pub fn set_alignment_check(_enable: bool) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
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

pub fn enable_instruction_cache() {
    #[cfg(all(not(test), target_arch = "aarch64"))]
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

pub fn enable_data_cache() {
    #[cfg(all(not(test), target_arch = "aarch64"))]
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

pub fn update_translation_table_entry(_translation_table_entry: u64, _mva: u64) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
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
pub fn cache_range_operation(start: u64, length: u64, op: CpuFlushType) {
    let cacheline_alignment = data_cache_line_len() - 1;
    let mut aligned_addr = start - (start & cacheline_alignment);
    let end_addr = start + length;

    loop {
        match op {
            CpuFlushType::EfiCpuFlushTypeWriteBack => clean_data_entry_by_mva(aligned_addr),
            CpuFlushType::EFiCpuFlushTypeInvalidate => invalidate_data_cache_entry_by_mva(aligned_addr),
            CpuFlushType::EfiCpuFlushTypeWriteBackInvalidate => clean_and_invalidate_data_entry_by_mva(aligned_addr),
        }

        aligned_addr += cacheline_alignment;
        if aligned_addr >= end_addr {
            break;
        }
    }

    #[cfg(all(not(test), target_arch = "aarch64"))]
    unsafe {
        asm!("dsb sy", options(nostack));
    }
}

fn data_cache_line_len() -> u64 {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    {
        let ctr_el0 = unsafe {
            let ctr_el0: u64;
            asm!("mrs {}, ctr_el0", out(reg) ctr_el0);
            ctr_el0
        };
        return 4 << ((ctr_el0 >> 16) & 0xf);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        // For all other cases, return 64 bytes
        64_u64
    }
}

fn clean_data_entry_by_mva(_mva: u64) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    unsafe {
        asm!("dc cvac, {}", in(reg) _mva, options(nostack, preserves_flags));
    }
}

fn invalidate_data_cache_entry_by_mva(_mva: u64) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    unsafe {
        asm!("dc ivac, {}", in(reg) _mva, options(nostack, preserves_flags));
    }
}

fn clean_and_invalidate_data_entry_by_mva(_mva: u64) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    unsafe {
        asm!("dc civac, {}", in(reg) _mva, options(nostack, preserves_flags));
    }
}

// Helper function to check if this page table is active
pub fn is_this_page_table_active(page_table_base: PhysicalAddress) -> bool {
    // Check the TTBR0 register to see if this page table matches
    // our base
    let mut _ttbr0: u64 = 0;
    let _current_el = get_current_el();
    #[cfg(all(not(test), target_arch = "aarch64"))]
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
        #[cfg(all(not(test), target_arch = "aarch64"))]
        unsafe {
            let sctlr: u64;
            match _current_el {
                2 => asm!("mrs {}, sctlr_el2", out(reg) sctlr),
                1 => asm!("mrs {}, sctlr_el1", out(reg) sctlr),
                invalid_el => panic!("Invalid current EL {}", invalid_el),
            }
            return sctlr & 0x1 == 1;
        }
        false
    }
}
