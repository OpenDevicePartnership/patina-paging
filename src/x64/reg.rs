#[allow(unused_imports)]
use core::arch::asm;

use super::structs::CR3_PAGE_BASE_ADDRESS_MASK;

/// Write CR3 register. Also invalidates TLB.
pub unsafe fn write_cr3(_value: u64) {
    #[cfg(not(test))]
    {
        unsafe {
            asm!("mov cr3, {}", in(reg) _value, options(nostack, preserves_flags));
        }
    }
}

/// Read CR3 register.
pub unsafe fn read_cr3() -> u64 {
    let mut _value = 0u64;

    #[cfg(not(test))]
    {
        unsafe {
            asm!("mov {}, cr3", out(reg) _value, options(nostack, preserves_flags));
        }
    }

    _value
}

/// Invalidate the TLB by reloading the CR3 register if the base is currently
/// being used
pub unsafe fn invalidate_tlb(base: u64) {
    let value = base & CR3_PAGE_BASE_ADDRESS_MASK;
    if read_cr3() == value {
        write_cr3(value);
    }
}
