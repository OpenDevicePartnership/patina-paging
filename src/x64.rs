#[allow(unused_imports)]
use core::arch::asm;
use core::ptr;

mod pagetablestore;
mod structs;
#[cfg(test)]
mod tests;

use pagetablestore::X64PageTableEntry;
use structs::{CR3_PAGE_BASE_ADDRESS_MASK, MAX_VA_4_LEVEL, MAX_VA_5_LEVEL, ZERO_VA_4_LEVEL, ZERO_VA_5_LEVEL};

use crate::{
    MemoryAttributes, PageTable, PagingType, PtResult,
    arch::PageTableHal,
    page_allocator::PageAllocator,
    paging::PageTableInternal,
    structs::{PAGE_SIZE, PageLevel, VirtualAddress},
};

pub struct X64PageTable<P: PageAllocator> {
    internal: PageTableInternal<P, PageTableArchX64>,
}

impl<P: PageAllocator> X64PageTable<P> {
    pub fn new(page_allocator: P, paging_type: PagingType) -> PtResult<Self> {
        let internal = PageTableInternal::new(page_allocator, paging_type)?;
        Ok(Self { internal })
    }

    /// Create a page table from existing page table base. This can be used to
    /// parse or edit an existing identity mapped page table.
    ///
    /// # Safety
    ///
    /// This routine will return a struct that will parse memory addresses from
    /// PFNs in the provided base, so that caller is responsible for ensuring
    /// safety of that base.
    ///
    pub unsafe fn from_existing(base: u64, page_allocator: P, paging_type: PagingType) -> PtResult<Self> {
        let internal = unsafe { PageTableInternal::from_existing(base, page_allocator, paging_type)? };
        Ok(Self { internal })
    }

    /// Consumes the page table structure and returns the page table root.
    pub fn into_page_table_root(self) -> u64 {
        self.internal.into_page_table_root()
    }
}

impl<P: PageAllocator> PageTable for X64PageTable<P> {
    fn map_memory_region(
        &mut self,
        address: u64,
        size: u64,
        attributes: crate::MemoryAttributes,
    ) -> crate::PtResult<()> {
        self.internal.map_memory_region(address, size, attributes)
    }

    fn unmap_memory_region(&mut self, address: u64, size: u64) -> crate::PtResult<()> {
        self.internal.unmap_memory_region(address, size)
    }

    fn remap_memory_region(
        &mut self,
        address: u64,
        size: u64,
        attributes: crate::MemoryAttributes,
    ) -> crate::PtResult<()> {
        self.internal.remap_memory_region(address, size, attributes)
    }

    fn install_page_table(&mut self) -> crate::PtResult<()> {
        self.internal.install_page_table()
    }

    fn query_memory_region(&self, address: u64, size: u64) -> crate::PtResult<crate::MemoryAttributes> {
        self.internal.query_memory_region(address, size)
    }

    fn dump_page_tables(&self, address: u64, size: u64) -> PtResult<()> {
        self.internal.dump_page_tables(address, size)
    }
}

pub(crate) struct PageTableArchX64;

impl PageTableHal for PageTableArchX64 {
    type PTE = X64PageTableEntry;
    const DEFAULT_ATTRIBUTES: MemoryAttributes = MemoryAttributes::empty();

    /// Zero a page of memory
    ///
    /// # Safety
    /// This function is unsafe because it operates on raw pointers. It requires the caller to ensure the VA passed in
    /// is mapped.
    unsafe fn zero_page(page: VirtualAddress) {
        // This cast must occur as a mutable pointer to a u8, as otherwise the compiler can optimize out the write,
        // which must not happen as that would violate break before make and have garbage in the page table.
        unsafe { ptr::write_bytes(Into::<u64>::into(page) as *mut u8, 0, PAGE_SIZE as usize) };
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

    fn invalidate_tlb(va: VirtualAddress) {
        pagetablestore::invalidate_tlb(va.into());
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
        unsafe {
            write_cr3(base);
        }
        Ok(())
    }

    fn level_supports_pa_entry(level: crate::structs::PageLevel) -> bool {
        matches!(level, PageLevel::Level3 | PageLevel::Level2 | PageLevel::Level1)
    }
}

/// Write CR3 register. Also invalidates TLB.
unsafe fn write_cr3(_value: u64) {
    #[cfg(all(not(test), target_arch = "x86_64"))]
    {
        unsafe {
            asm!("mov cr3, {}", in(reg) _value, options(nostack, preserves_flags));
        }
    }
}

/// Read CR3 register.
fn read_cr3() -> u64 {
    let mut _value = 0u64;

    #[cfg(all(not(test), target_arch = "x86_64"))]
    {
        unsafe {
            asm!("mov {}, cr3", out(reg) _value, options(nostack, preserves_flags));
        }
    }

    _value
}
#[cfg(test)]
mod zero_page_tests {
    use super::*;
    use crate::structs::VirtualAddress;

    #[test]
    fn test_zero_page_zeros_entire_page() {
        // Allocate a page-sized Vec<u8> and fill it with non-zero values
        let mut page = vec![0xAAu8; PAGE_SIZE as usize];
        let va = VirtualAddress::new(page.as_mut_ptr() as u64);

        // SAFETY: We have exclusive access to the page buffer
        unsafe {
            PageTableArchX64::zero_page(va);
        }

        // Assert all bytes are zero
        assert!(page.iter().all(|&b| b == 0), "Not all bytes were zeroed");
    }
}
