#[allow(unused_imports)]
use core::arch::asm;

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
    structs::{PageLevel, VirtualAddress},
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

    // This function must not be inlined to ensure that the register reads and writes don't affect the
    // caller's registers. It has been viewed that this function is inlined several layers up the stack and has
    // corrupted the rdi register, causing a crash.
    #[inline(never)]
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
            options(nostack)
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
