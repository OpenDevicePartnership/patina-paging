///
/// Implements x64 paging. Supports below modes
/// - x64 4KB 5 level paging
/// - x64 4KB 4 level paging
///
use crate::{
    page_allocator::PageAllocator,
    page_table_error::{PtError, PtResult},
    PageTable, PagingType,
};

use super::{
    pagetablestore::X64PageTableStore,
    reg::{invalidate_tlb, write_cr3},
    structs::{PageLevel, PhysicalAddress, VirtualAddress, MAX_PML4_VA, MAX_PML5_VA, PAGE_SIZE},
};

/// Below struct is used to manage the page table hierarchy. It keeps track of
/// page table base and create any intermediate page tables required with
/// allocator.
pub struct X64PageTable<A: PageAllocator> {
    // Points to the base of top level page table(always in canonical form)
    base: PhysicalAddress,
    page_allocator: A,
    paging_type: PagingType,

    highest_page_level: PageLevel,
    lowest_page_level: PageLevel,
}

impl<A: PageAllocator> X64PageTable<A> {
    pub fn new(mut page_allocator: A, paging_type: PagingType) -> PtResult<Self> {
        // Allocate the top level page table(PML5)
        let base = page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE)?;
        assert!(PhysicalAddress::new(base).is_4kb_aligned());

        // SAFETY: We just allocated the page, so it is safe to use it.
        unsafe { Self::from_existing(base, page_allocator, paging_type) }
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
    pub unsafe fn from_existing(base: u64, page_allocator: A, paging_type: PagingType) -> PtResult<Self> {
        let base = PhysicalAddress::new(base);
        if !base.is_4kb_aligned() {
            return Err(PtError::UnalignedPageBase);
        }

        // For the given paging type identify the highest and lowest page levels.
        // This is used during page building to stop the recursion.
        let (highest_page_level, lowest_page_level) = match paging_type {
            PagingType::Paging4KB5Level => (PageLevel::Pml5, PageLevel::Pt),
            PagingType::Paging4KB4Level => (PageLevel::Pml4, PageLevel::Pt),
            _ => return Err(PtError::InvalidParameter),
        };

        Ok(Self { base, page_allocator, paging_type, highest_page_level, lowest_page_level })
    }

    /// Consumes the page table structure and returns the page table root.
    pub fn into_page_table_root(self) -> u64 {
        self.base.into()
    }

    pub fn allocate_page(&mut self) -> PtResult<PhysicalAddress> {
        let base = self.page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE)?;
        let base = PhysicalAddress::new(base);
        if !base.is_4kb_aligned() {
            panic!("allocate_page() returned unaligned page");
        }

        Ok(base)
    }

    // For a given memory range, the number of intermediate page table entries
    // can span across multiple pages(as shown below), here PML4E is spread
    // across 3 pages(first and last page not fully occupied), the reason for
    // this spread is because of number of parent entries(PML5E). For example,
    // when processing the offsets in 0x301D600000000 - 0x602AC00000000 VA
    // range, we will have 4 entries([3-6]) for PML5 and 5 entries for
    // PML4([3-7]). But the actual number of PML4 entires required are [3-511] +
    // [0-511] + [0-511] + [0-7] = 1541 entries.

    // 0x000301D600000000 :
    //       |      PML5|     PML4| PDP/PML3|  PD/PML2|  PT/PML1|    Physical
    // 000000|0000000011|000000011|101011000|000000000|000000000|000000000000
    //      0|         3|        3|      344|        0|        0|           0 Decimal

    // 0x000603ABFFFFFFFF :
    //       |      PML5|     PML4| PDP/PML3|  PD/PML2|  PT/PML1|    Physical
    // 000000|0000000110|000000111|010101111|111111111|111111111|111111111111
    //      0|         6|        7|      175|      511|      511|        4095 Decimal

    // Because of this, the page walking logic should appropriately split the
    // memory ranges when jumping to next level page tables. Just relying on
    // indices at the current level do not work! Below is a recursive
    // implementation of it.

    //  │               │  ┌─────┐       │
    //  │               │  │     │       │
    //  │               │  ├─────┤       │
    //  │               │  │     │       │
    //  │               │  ├─────┤       │
    //  │               └─►│PML4E│       │
    //  │               │  ├─────┤       │
    //  │               │  │PML4E|       │
    //  │          ┌──────►└─────┘       │
    //  │          │    │  ┌─────┐       │  ┌─────┐
    //  │          │    │  │PML4E│       │  │     │
    //  │          │    │  ├─────┤       │  ├─────┤
    //  │          │    │  │PML4E│       │  │     │
    //  │          │    │  ├─────┤       │  ├─────┤
    //  │          │    └─►│PML4E│       │  │PDPE │
    //  │          │    │  ├─────┤       │  ├─────┤
    //  │          │    │  │PML4E|       |  │PDPE |
    //  │          │ ┌────►└─────┘   ┌─────►└─────┘
    //  │  ┌─────┐ │ │  │  ┌─────┐   │   │  ┌─────┐
    //  │  │PML5E│─┘ │  │  │PML4E|───┘   │  │PDPE |
    //  │  ├─────┤   │  │  ├─────┤       │  ├─────┤
    //  │  │PML5E│───┘  └─►│PML4E│───┐   │  │PDPE │
    //  │  ├─────┤         ├─────┤   │   │  ├─────┤
    //  └─►│PML5E├───┐     │     │   │   └─►│PDPE │───┐
    //     ├─────┤   │     ├─────┤   │      ├─────┤   │
    //     │     │   │     │     │   │      │     │   │
    //     └─────┘   └────►└─────┘   └─────►└─────┘   └───►

    fn map_memory_region_internal(
        &mut self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
        attributes: u64,
    ) -> PtResult<()> {
        let mut va = start_va;

        let table = X64PageTableStore::new(base, level, self.paging_type, start_va, end_va);
        if level == self.lowest_page_level {
            for mut entry in table {
                entry.update_fields(attributes, va.into())?;

                // get max va addressable by current entry
                va = va.get_next_va(level);
            }
            return Ok(());
        }

        for mut entry in table {
            if !entry.present() {
                let pa = self.allocate_page()?;
                entry.update_fields(attributes, pa)?;
            }
            let next_base = entry.get_canonical_page_table_base();

            // split the va range appropriately for the next level pages

            // start of the next level va. It will be same as current va
            let next_level_start_va = va;

            // get max va addressable by current entry
            let curr_va_ceil = va.round_up(level);

            // end of next level va. It will be minimum of next va and end va
            let next_level_end_va = VirtualAddress::min(curr_va_ceil, end_va);

            self.map_memory_region_internal(
                next_level_start_va,
                next_level_end_va,
                (level as u64 - 1).into(),
                next_base,
                attributes,
            )?;

            va = va.get_next_va(level);
        }

        Ok(())
    }

    fn unmap_memory_region_internal(
        &self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
    ) -> PtResult<()> {
        let mut va = start_va;

        let table = X64PageTableStore::new(base, level, self.paging_type, start_va, end_va);
        if level == self.lowest_page_level {
            for entry in table {
                if !entry.present() {
                    continue;
                }

                entry.set_present(false);
            }
            return Ok(());
        }

        for entry in table {
            if !entry.present() {
                continue;
            }
            let next_base = entry.get_canonical_page_table_base();

            // split the va range appropriately for the next level pages

            // start of the next level va. It will be same as current va
            let next_level_start_va = va;

            // get max va addressable by current entry
            let curr_va_ceil = va.round_up(level);

            // end of next level va. It will be minimum of next va and end va
            let next_level_end_va = VirtualAddress::min(curr_va_ceil, end_va);

            self.unmap_memory_region_internal(
                next_level_start_va,
                next_level_end_va,
                (level as u64 - 1).into(),
                next_base,
            )?;

            va = va.get_next_va(level);
        }

        Ok(())
    }

    fn remap_memory_region_internal(
        &self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
        attributes: u64,
    ) -> PtResult<()> {
        let mut va = start_va;

        let table = X64PageTableStore::new(base, level, self.paging_type, start_va, end_va);
        if level == self.lowest_page_level {
            for mut entry in table {
                if !entry.present() {
                    return Err(PtError::NoMapping);
                }

                entry.update_fields(attributes, va.into())?;

                // get max va addressable by current entry
                va = va.get_next_va(level);
            }
            return Ok(());
        }

        for entry in table {
            if !entry.present() {
                return Err(PtError::NoMapping);
            }

            let next_base = entry.get_canonical_page_table_base();

            // split the va range appropriately for the next level pages

            // start of the next level va. It will be same as current va
            let next_level_start_va = va;

            // get max va addressable by current entry
            let curr_va_ceil = va.round_up(level);

            // end of next level va. It will be minimum of next va and end va
            let next_level_end_va = VirtualAddress::min(curr_va_ceil, end_va);

            self.remap_memory_region_internal(
                next_level_start_va,
                next_level_end_va,
                (level as u64 - 1).into(),
                next_base,
                attributes,
            )?;

            va = va.get_next_va(level);
        }

        Ok(())
    }

    fn query_memory_region_internal(
        &self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
        prev_attributes: &mut u64,
    ) -> PtResult<u64> {
        let mut va = start_va;

        let table = X64PageTableStore::new(base, level, self.paging_type, start_va, end_va);
        if level == self.lowest_page_level {
            for entry in table {
                if !entry.present() {
                    return Err(PtError::NoMapping);
                }

                // Given memory range can span multiple page table entries, in such
                // scenario, the expectation is all entries should have same attributes.
                let current_attributes = entry.get_attributes();
                if *prev_attributes == 0 {
                    *prev_attributes = current_attributes;
                }

                if *prev_attributes != current_attributes {
                    return Err(PtError::IncompatibleMemoryAttributes);
                }
            }
            return Ok(*prev_attributes);
        }

        for entry in table {
            if !entry.present() {
                return Err(PtError::NoMapping);
            }
            let next_base = entry.get_canonical_page_table_base();

            // split the va range appropriately for the next level pages

            // start of the next level va. It will be same as current va
            let next_level_start_va = va;

            // get max va addressable by current entry
            let curr_va_ceil = va.round_up(level);

            // end of next level va. It will be minimum of next va and end va
            let next_level_end_va = VirtualAddress::min(curr_va_ceil, end_va);

            self.query_memory_region_internal(
                next_level_start_va,
                next_level_end_va,
                (level as u64 - 1).into(),
                next_base,
                prev_attributes,
            )?;

            va = va.get_next_va(level);
        }

        Ok(*prev_attributes)
    }

    fn validate_address_range(&self, address: VirtualAddress, size: u64) -> PtResult<()> {
        // Overflow check
        address.try_add(size)?;

        // Check the memory range
        match self.paging_type {
            PagingType::Paging4KB5Level => {
                if address + size > VirtualAddress::new(MAX_PML5_VA) {
                    return Err(PtError::InvalidMemoryRange);
                }
            }
            PagingType::Paging4KB4Level => {
                if address + size > VirtualAddress::new(MAX_PML4_VA) {
                    return Err(PtError::InvalidMemoryRange);
                }
            }
            _ => return Err(PtError::InvalidParameter),
        }

        match self.paging_type {
            PagingType::Paging4KB5Level | PagingType::Paging4KB4Level => {
                if size == 0 || !address.is_4kb_aligned() {
                    return Err(PtError::UnalignedAddress);
                }

                // Check the memory range is aligned
                if !(address + size).is_4kb_aligned() {
                    return Err(PtError::UnalignedMemoryRange);
                }
            }
            _ => return Err(PtError::InvalidParameter),
        }

        Ok(())
    }
}

impl<A: PageAllocator> PageTable for X64PageTable<A> {
    fn map_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        // We map until next alignment
        let start_va = address;
        let end_va = address + size - 1;

        // println!("start {:X} end {:X}", start_va, end_va);

        let result = self.map_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, attributes);

        unsafe { invalidate_tlb(self.base.into()) };

        result
    }

    fn unmap_memory_region(&mut self, address: u64, size: u64) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + size - 1;

        let result = self.unmap_memory_region_internal(start_va, end_va, self.highest_page_level, self.base);

        unsafe { invalidate_tlb(self.base.into()) };

        result
    }

    fn remap_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + size - 1;

        // make sure the memory region has same attributes set
        let mut prev_attributes = 0;
        self.query_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, &mut prev_attributes)?;

        let result =
            self.remap_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, attributes);

        unsafe { invalidate_tlb(self.base.into()) };

        result
    }

    fn install_page_table(&self) -> PtResult<()> {
        let value: u64 = self.base.into();
        unsafe { write_cr3(value) };
        Ok(())
    }

    fn query_memory_region(&self, address: u64, size: u64) -> PtResult<u64> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + size - 1;

        let mut prev_attributes = 0;
        self.query_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, &mut prev_attributes)
    }
}
