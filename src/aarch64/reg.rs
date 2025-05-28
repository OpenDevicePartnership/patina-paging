use crate::structs::{PhysicalAddress, PAGE_SIZE};

cfg_if::cfg_if! {
    if #[cfg(all(not(test), target_arch = "aarch64"))] {
        use core::arch::{asm, global_asm};
        global_asm!(include_str!("replace_table_entry.asm"));
        // Use efiapi for the consistent calling convention.
        extern "efiapi" {
            pub(crate) fn replace_live_xlat_entry(entry_ptr: u64, val: u64, addr: u64);
        }
    }
}

macro_rules! read_sysreg {
  ($reg:expr, $default:expr) => {{
    let mut _value: u64 = $default;
    let _ = $reg; // Helps prevent identical code being generated in tests.
    #[cfg(all(not(test), target_arch = "aarch64"))]
    unsafe {
      asm!(concat!("mrs {}, ", $reg), out(reg) _value);
    }
    _value
  }};
}

macro_rules! write_sysreg {
  ($reg:expr, $value:expr) => {{
    let _value: u64 = $value;
    let _ = $reg; // Helps prevent identical code being generated in tests.
    #[cfg(all(not(test), target_arch = "aarch64"))]
    unsafe {
      asm!(concat!("msr ", $reg, ", {}"), in(reg) _value);
    }
  }};
}

pub(crate) enum CpuFlushType {
    _EfiCpuFlushTypeWriteBackInvalidate,
    _EfiCpuFlushTypeWriteBack,
    EFiCpuFlushTypeInvalidate,
}

#[inline(always)]
fn instruction_barrier() {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    unsafe {
        asm!("isb", options(nostack));
    }
}

#[inline(always)]
fn data_barrier() {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    unsafe {
        asm!("dsb sy", options(nostack));
    }
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

pub(crate) fn get_current_el() -> u64 {
    // Default to EL2
    let current_el: u64 = read_sysreg!("CurrentEL", 8);

    match current_el {
        0x0C => 3,
        0x08 => 2,
        0x04 => 1,
        _ => panic!("Invalid current EL {}", current_el),
    }
}

pub(crate) fn set_tcr(tcr: u64) {
    let current_el = get_current_el();
    if current_el == 2 {
        write_sysreg!("tcr_el2", tcr);
    } else if current_el == 1 {
        write_sysreg!("tcr_el1", tcr);
    } else {
        panic!("Invalid current EL {}", current_el);
    }
    instruction_barrier();
}

pub(crate) fn set_ttbr0(ttbr0: u64) {
    let current_el = get_current_el();
    if current_el == 2 {
        write_sysreg!("ttbr0_el2", ttbr0);
    } else if current_el == 1 {
        write_sysreg!("ttbr0_el1", ttbr0);
    } else {
        panic!("Invalid current EL {}", current_el);
    }
    instruction_barrier();
}

pub(crate) fn set_mair(mair: u64) {
    let current_el = get_current_el();
    if current_el == 2 {
        write_sysreg!("mair_el2", mair);
    } else if current_el == 1 {
        write_sysreg!("mair_el1", mair);
    } else {
        panic!("Invalid current EL {}", current_el);
    }
    instruction_barrier();
}

pub(crate) fn is_mmu_enabled() -> bool {
    let sctlr: u64 = match get_current_el() {
        2 => read_sysreg!("sctlr_el2", 0x1),
        1 => read_sysreg!("sctlr_el1", 0x1),
        invalid_el => panic!("Invalid current EL {}", invalid_el),
    };

    sctlr & 0x1 == 1
}

pub(crate) fn enable_mmu() {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    unsafe {
        let current_el = get_current_el();
        if current_el == 2 {
            asm!(
                "mrs {val}, sctlr_el2",
                "orr {val}, {val}, #0x1",
                "tlbi alle2",
                "dsb nsh",
                "isb",
                "msr sctlr_el2, {val}",
                val = out(reg) _,
                options(nostack)
            );
        } else if current_el == 1 {
            asm!(
                "mrs {val}, sctlr_el1",
                "orr {val}, {val}, #0x1",
                "tlbi vmalle1",
                "dsb nsh",
                "isb",
                "msr sctlr_el1, {val}",
                val = out(reg) _,
                options(nostack)
            );
        } else {
            panic!("Invalid current EL {}", current_el);
        }
        asm!("isb", options(nostack));
    }
}

pub(crate) fn set_stack_alignment_check(enable: bool) {
    let current_el = get_current_el();
    if current_el == 2 {
        let sctlr = read_sysreg!("sctlr_el2", 0);
        match enable {
            true => write_sysreg!("sctlr_el2", sctlr | 0x8),
            false => write_sysreg!("sctlr_el2", sctlr & !0x8),
        }
    } else if current_el == 1 {
        let sctlr = read_sysreg!("sctlr_el1", 0);
        match enable {
            true => write_sysreg!("sctlr_el1", sctlr | 0x8),
            false => write_sysreg!("sctlr_el1", sctlr & !0x8),
        }
    } else {
        panic!("Invalid current EL {}", current_el);
    }
    data_barrier();
    instruction_barrier();
}

pub(crate) fn set_alignment_check(enable: bool) {
    let current_el = get_current_el();
    if current_el == 2 {
        let sctlr = read_sysreg!("sctlr_el2", 0);
        match enable {
            true => write_sysreg!("sctlr_el2", sctlr | 0x2),
            false => write_sysreg!("sctlr_el2", sctlr & !0x2),
        }
    } else if current_el == 1 {
        let sctlr = read_sysreg!("sctlr_el1", 0);
        match enable {
            true => write_sysreg!("sctlr_el1", sctlr | 0x2),
            false => write_sysreg!("sctlr_el1", sctlr & !0x2),
        }
    } else {
        panic!("Invalid current EL {}", current_el);
    }
    data_barrier();
    instruction_barrier();
}

pub(crate) fn enable_instruction_cache() {
    let current_el = get_current_el();
    if current_el == 2 {
        let sctlr = read_sysreg!("sctlr_el2", 0);
        write_sysreg!("sctlr_el2", sctlr | 0x1000);
    } else if current_el == 1 {
        let sctlr = read_sysreg!("sctlr_el1", 0);
        write_sysreg!("sctlr_el1", sctlr | 0x1000);
    } else {
        panic!("Invalid current EL {}", current_el);
    }
    data_barrier();
    instruction_barrier();
}

pub(crate) fn enable_data_cache() {
    let current_el = get_current_el();
    if current_el == 2 {
        let sctlr = read_sysreg!("sctlr_el2", 0);
        write_sysreg!("sctlr_el2", sctlr | 0x4);
    } else if current_el == 1 {
        let sctlr = read_sysreg!("sctlr_el1", 0);
        write_sysreg!("sctlr_el1", sctlr | 0x4);
    } else {
        panic!("Invalid current EL {}", current_el);
    }
    data_barrier();
    instruction_barrier();
}

pub(crate) fn update_translation_table_entry(_translation_table_entry: u64, _mva: u64) {
    #[cfg(all(not(test), target_arch = "aarch64"))]
    unsafe {
        let current_el = get_current_el();
        let pfn = _mva >> 12;
        let mut sctlr: u64;
        asm!("dsb     nshst", options(nostack));
        if current_el == 2 {
            asm!(
                "tlbi vae2, {}",
                "mrs {}, sctlr_el2",
                in(reg) pfn,
                out(reg) sctlr,
                options(nostack)
            );
        } else if current_el == 1 {
            asm!(
                "tlbi vaae1, {}",
                "mrs {}, sctlr_el1",
                in(reg) pfn,
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

    data_barrier();
}

fn data_cache_line_len() -> u64 {
    // Default to 64 bytes
    let ctr_el0 = read_sysreg!("ctr_el0", 0x1000000);
    4 << ((ctr_el0 >> 16) & 0xf)
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
pub(crate) fn is_this_page_table_active(page_table_base: PhysicalAddress) -> bool {
    // Check the TTBR0 register to see if this page table matches
    // our base
    let mut _ttbr0: u64 = 0;
    let current_el = get_current_el();
    let ttbr0 = match current_el {
        2 => read_sysreg!("ttbr0_el2", 0),
        1 => read_sysreg!("ttbr0_el1", 0),
        invalid_el => panic!("Invalid current EL {}", invalid_el),
    };

    if ttbr0 != u64::from(page_table_base) {
        false
    } else {
        // Check to see if MMU is enabled
        is_mmu_enabled()
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
pub(crate) unsafe fn zero_page(page: u64) {
    // If the MMU is diabled, invalidate the cache so that any stale data does
    // not get later evicted to memory.
    if !is_mmu_enabled() {
        cache_range_operation(page, PAGE_SIZE, CpuFlushType::EFiCpuFlushTypeInvalidate);
    }

    #[cfg(all(not(test), target_arch = "aarch64"))]
    {
        let mut addr = page;
        for i in 0..256 {
            asm!(
                "stp {zero}, {zero}, [{addr}], #16",    // Store 0 to the next 16 bytes of the page
                addr = inout(reg) addr,
                zero = in(reg) 0_u64,
                options(nostack, preserves_flags)
            );
        }
    }
}
