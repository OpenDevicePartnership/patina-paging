use crate::{page_allocator::PageAllocator, MemoryAttributes, PageTable, PagingType, PtError, PtResult};

use core::arch::asm;

use super::{
    pagetablestore::AArch64PageTableStore,
    structs::{PageLevel, PhysicalAddress, VirtualAddress, MAX_VA, PAGE_SIZE},
};

/// Below struct is used to manage the page table hierarchy. It keeps track of
/// page table base and create any intermediate page tables required with
/// allocator. It uses `AArch64PageTableStore<T>` to interpret the pages
pub struct AArch64PageTable<A: PageAllocator> {
    // Points to the base of top level page table
    base: PhysicalAddress,
    page_allocator: A,
    paging_type: PagingType,

    highest_page_level: PageLevel,
    lowest_page_level: PageLevel,
}

impl<A: PageAllocator> AArch64PageTable<A> {
    pub fn new(mut page_allocator: A, paging_type: PagingType) -> PtResult<Self> {
        // Allocate the root page table
        let base = page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE)?;
        assert!(PhysicalAddress::new(base).is_4kb_aligned());

        // SAFETY: We just allocated the page, so it is safe to use it.
        unsafe { Self::from_existing(base, page_allocator, paging_type) }
    }

    /// Create a page table from existing page table root. This can be used to
    /// parse or edit an existing identity mapped page table.
    ///
    /// # Safety
    ///
    /// This routine will return a struct that will parse memory addresses from
    /// PFNs in the provided base, so that caller is responsible for ensuring
    /// safety of that base.
    ///
    pub unsafe fn from_existing(base: u64, page_allocator: A, paging_type: PagingType) -> PtResult<Self> {
        let base: PhysicalAddress = PhysicalAddress::new(base);
        if !base.is_4kb_aligned() {
            return Err(PtError::UnalignedPageBase);
        }

        // For the given paging type identify the highest and lowest page levels.
        // This is used during page building to stop the recursion.
        let (highest_page_level, lowest_page_level) = match paging_type {
            PagingType::AArch64PageTable4KB => (PageLevel::Lvl0, PageLevel::Lvl3),
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

    fn map_memory_region_internal(
        &mut self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
        attributes: MemoryAttributes,
    ) -> PtResult<()> {
        let mut va = start_va;

        let table = AArch64PageTableStore::new(base, level, self.paging_type, start_va, end_va);
        if level == self.lowest_page_level {
            for mut entry in table {
                entry.update_fields(attributes, va.into())?;

                // get max va addressable by current entry
                va = va.get_next_va(level);
            }
            return Ok(());
        }

        for mut entry in table {
            if !entry.is_valid() {
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

        let table = AArch64PageTableStore::new(base, level, self.paging_type, start_va, end_va);
        if level == self.lowest_page_level {
            for entry in table {
                if !entry.is_valid() {
                    continue;
                }

                entry.set_invalid();
            }
            return Ok(());
        }

        for entry in table {
            if !entry.is_valid() {
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
        attributes: MemoryAttributes,
    ) -> PtResult<()> {
        let mut va = start_va;

        let table = AArch64PageTableStore::new(base, level, self.paging_type, start_va, end_va);
        if level == self.lowest_page_level {
            for mut entry in table {
                if !entry.is_valid() {
                    return Err(PtError::NoMapping);
                }

                entry.update_fields(attributes, va.into())?;

                // get max va addressable by current entry
                va = va.get_next_va(level);
            }
            return Ok(());
        }

        for entry in table {
            if !entry.is_valid() {
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
        prev_attributes: &mut MemoryAttributes,
    ) -> PtResult<MemoryAttributes> {
        let mut va = start_va;

        let table = AArch64PageTableStore::new(base, level, self.paging_type, start_va, end_va);
        if level == self.lowest_page_level {
            for entry in table {
                if !entry.is_valid() {
                    return Err(PtError::NoMapping);
                }

                // Given memory range can span multiple page table entries, in such
                // scenario, the expectation is all entries should have same attributes.
                let current_attributes = entry.get_attributes();
                if (*prev_attributes).is_empty() {
                    *prev_attributes = current_attributes;
                }

                if *prev_attributes != current_attributes {
                    return Err(PtError::IncompatibleMemoryAttributes);
                }
            }
            return Ok(*prev_attributes);
        }

        for entry in table {
            if !entry.is_valid() {
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

    #[cfg(test)]
    fn dump_page_tables_internal(
        &self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
    ) {
        let mut va = start_va;

        let table = AArch64PageTableStore::new(base, level, self.paging_type, start_va, end_va);
        if level == self.lowest_page_level {
            for entry in table {
                if !entry.is_valid() {
                    return;
                }

                // start of the next level va. It will be same as current va
                let next_level_start_va = va;

                // get max va addressable by current entry
                let curr_va_ceil = va.round_up(level);

                // end of next level va. It will be minimum of next va and end va
                let next_level_end_va = VirtualAddress::min(curr_va_ceil, end_va);

                let l: u64 = level.into();
                let range = format!("{}[{} {}]", "  ".repeat(5 - l as usize), next_level_start_va, next_level_end_va);
                println!("{}|{:48}{}", level, range, entry.dump_entry());

                va = va.get_next_va(level);
            }
            return;
        }

        for entry in table {
            if !entry.is_valid() {
                return;
            }
            let next_base = entry.get_canonical_page_table_base();

            // split the va range appropriately for the next level pages

            // start of the next level va. It will be same as current va
            let next_level_start_va = va;

            // get max va addressable by current entry
            let curr_va_ceil = va.round_up(level);

            // end of next level va. It will be minimum of next va and end va
            let next_level_end_va = VirtualAddress::min(curr_va_ceil, end_va);

            let l: u64 = level.into();
            let range = format!("{}[{} {}]", "  ".repeat(5 - l as usize), next_level_start_va, next_level_end_va);
            println!("{}|{:48}{}", level, range, entry.dump_entry());

            self.dump_page_tables_internal(
                next_level_start_va,
                next_level_end_va,
                (level as u64 - 1).into(),
                next_base,
            );

            va = va.get_next_va(level);
        }
    }

    // Private function to check if this page table is active
    fn _is_this_page_table_active(&self) -> bool {
        // Check the TTBR0 register to see if this page table matches
        // our base
        let ttbr0: u64;
        unsafe {
            asm!(
              "mrs {}, ttbr0_el1",
              out(reg) ttbr0
            );
        }

        if ttbr0 != u64::from(self.base) {
            false
        } else {
            // Check to see if MMU is enabled
            let sctlr: u64;
            unsafe {
                asm!(
                  "mrs {}, sctlr_el1",
                  out(reg) sctlr
                );
            }

            sctlr & 0x1 == 1
        }
    }

    fn validate_address_range(&self, address: VirtualAddress, size: u64) -> PtResult<()> {
        match self.paging_type {
            PagingType::AArch64PageTable4KB => {
                // Overflow check
                address.try_add(size)?;

                // Check the memory range
                if address + size > VirtualAddress::new(MAX_VA) {
                    return Err(PtError::InvalidMemoryRange);
                }

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

impl<A: PageAllocator> PageTable for AArch64PageTable<A> {
    fn map_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        // We map until next alignment
        let start_va = address;
        let end_va = address + size - 1;

        // println!("start {:X} end {:X}", start_va, end_va);

        self.map_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, attributes)
    }

    fn unmap_memory_region(&mut self, address: u64, size: u64) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + size - 1;

        self.unmap_memory_region_internal(start_va, end_va, self.highest_page_level, self.base)
    }

    fn install_page_table(&self) -> PtResult<()> {
        // This step will need to configure the MMU and then activate it on the newly created table.

        // TODO: Implement this function

        Ok(())
    }

    fn remap_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + size - 1;

        // make sure the memory region has same attributes set
        let mut prev_attributes = MemoryAttributes::empty();
        self.query_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, &mut prev_attributes)?;

        self.remap_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, attributes)
    }

    fn query_memory_region(&self, address: u64, size: u64) -> PtResult<MemoryAttributes> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + size - 1;

        let mut prev_attributes = MemoryAttributes::empty();
        self.query_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, &mut prev_attributes)
    }

    #[cfg(test)]
    fn dump_page_tables(&self, address: u64, size: u64) {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size).unwrap();

        let start_va = address;
        let end_va = address + size - 1;

        println!("start-end:[{} {}]", start_va, end_va);
        println!("{}", "-".repeat(130));
        self.dump_page_tables_internal(start_va, end_va, self.highest_page_level, self.base)
    }
}
