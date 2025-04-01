use super::structs::CR3_PAGE_BASE_ADDRESS_MASK;
#[allow(unused_imports)]
use core::arch::asm;

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
    unsafe {
        asm!(
        "cld",              // Clear the direction flag so that we increment rdi with each store
        "rep stosq",        // Repeat the store of qword in rax to [rdi] rcx times
        in("rcx") 0x200,    // we write 512 qwords (4096 bytes)
        in("rdi") _page,    // start at the page
        in("rax") 0,        // store 0
        options(nostack, preserves_flags)
        );
    }
}
