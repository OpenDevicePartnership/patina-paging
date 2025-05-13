#[allow(unused_imports)]
use core::arch::asm;

use pagetablestore::X64PageTableEntry;
use structs::*;

use crate::{arch::PageTableArch, structs::VirtualAddress, PagingType, PtResult};

pub struct PageTableX64;
mod pagetablestore;
mod structs;

impl PageTableArch for PageTableX64 {
    type PTE = X64PageTableEntry;

    unsafe fn zero_page(base: VirtualAddress) {
        let _page: u64 = base.into();
        #[cfg(all(not(test), target_arch = "x86_64"))]
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

    fn paging_type_supported(paging_type: PagingType) -> PtResult<()> {
        match paging_type {
            PagingType::Paging5Level => Ok(()),
            PagingType::Paging4Level => Ok(()),
        }
    }

    fn get_zero_va(paging_type: PagingType) -> PtResult<VirtualAddress> {
        match paging_type {
            PagingType::Paging5Level => Ok(ZERO_VA_5_LEVEL.into()),
            PagingType::Paging4Level => Ok(ZERO_VA_4_LEVEL.into()),
        }
    }

    fn invalidate_tlb(va: Option<VirtualAddress>) {
        if let Some(va) = va {
            let _address: u64 = va.into();
            #[cfg(all(not(test), target_arch = "x86_64"))]
            unsafe {
                asm!("mfence", "invlpg [{}]", in(reg) _address);
            }
        } else {
            // Invalidate the whole TLB
            // SAFETY: This writing back the saem value as the current CR3.
            unsafe { write_cr3(read_cr3()) };
        }
    }

    fn get_max_va(paging_type: PagingType) -> PtResult<VirtualAddress> {
        match paging_type {
            PagingType::Paging5Level => Ok(MAX_VA_5_LEVEL.into()),
            PagingType::Paging4Level => Ok(MAX_VA_4_LEVEL.into()),
        }
    }

    fn is_table_active(base: u64) -> bool {
        read_cr3() == (base & CR3_PAGE_BASE_ADDRESS_MASK)
    }

    unsafe fn install_page_table(base: u64) -> PtResult<()> {
        write_cr3(base);
        Ok(())
    }
}

/// Write CR3 register. Also invalidates TLB.
pub(crate) unsafe fn write_cr3(_value: u64) {
    #[cfg(all(not(test), target_arch = "x86_64"))]
    {
        unsafe {
            asm!("mov cr3, {}", in(reg) _value, options(nostack, preserves_flags));
        }
    }
}

/// Read CR3 register.
pub(crate) fn read_cr3() -> u64 {
    let mut _value = 0u64;

    #[cfg(all(not(test), target_arch = "x86_64"))]
    {
        unsafe {
            asm!("mov {}, cr3", out(reg) _value, options(nostack, preserves_flags));
        }
    }

    _value
}
