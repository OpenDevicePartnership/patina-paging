use core::marker::PhantomData;

use crate::{
    arch::PageTableArch,
    arch::PageTableEntry,
    page_allocator::PageAllocator,
    structs::{PageLevel, PhysicalAddress, VirtualAddress, PAGE_SIZE, SELF_MAP_INDEX, ZERO_VA_INDEX},
    MemoryAttributes, PagingType, PtError, PtResult, RangeMappingState,
};

pub struct PageTablesInternal<P: PageAllocator, Arch: PageTableArch> {
    base: PhysicalAddress,
    page_allocator: P,
    paging_type: PagingType,
    zero_va_pt_pa: Option<PhysicalAddress>,
    _arch: PhantomData<Arch>,
}

impl<P: PageAllocator, Arch: PageTableArch> PageTablesInternal<P, Arch> {
    pub fn new(mut page_allocator: P, paging_type: PagingType) -> PtResult<Self> {
        Arch::paging_type_supported(paging_type)?;

        // Allocate the top level page table
        let base = page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, true)?;
        assert!(PhysicalAddress::new(base).is_page_aligned());

        // SAFETY: We just allocated the page, so it is safe to use it.
        // We always need to zero any pages, as our contract with the page_allocator does not specify that we will
        // get zeroed pages. Random data in the page could confuse this code and make us believe there are existing
        // entries in the page table.

        // we have not installed this page table, we can't use our VA range to zero page or
        // rely on self-map, so we have to rely on the identity mapping for the root page
        unsafe { Arch::zero_page(base.into()) };

        // SAFETY: We just allocated the page and the top level is zeroed so it is safe to use it.
        let mut pt = unsafe { Self::from_existing(base, page_allocator, paging_type)? };

        // Setup the self-mapping for the top level page table.
        let mut self_map_entry = Arch::PTE::new(
            pt.base.into(),
            SELF_MAP_INDEX,
            paging_type.root_level(),
            paging_type,
            pt.base.into(),
            false,
        );

        // create it with permissive attributes
        self_map_entry.update_fields(MemoryAttributes::empty(), pt.base, false)?;

        // Setup the zero VA entry to allow for zeroing pages before putting them in the page table.
        let mut table_base = pt.base;
        let mut level = paging_type.root_level();
        let mut index = ZERO_VA_INDEX;
        let zero_va = Arch::get_zero_va(paging_type)?;
        while let Some(next_level) = level.next_level() {
            let new_table = pt.borrow_allocator().allocate_page(PAGE_SIZE, PAGE_SIZE, false)?;

            // SAFETY: We just allocated the page, so it is safe to use it.
            unsafe { Arch::zero_page(new_table.into()) };

            let mut entry = Arch::PTE::new(table_base, index, level, paging_type, zero_va, false);
            entry.update_fields(MemoryAttributes::empty(), PhysicalAddress::new(new_table), false)?;

            // After the first-level index, all other indexes are 0.
            index = 0;
            level = next_level;
            table_base = PhysicalAddress::new(new_table);
        }

        // Create the leaf zero VA entry.
        let mut entry = Arch::PTE::new(table_base.into(), 0, level, paging_type, zero_va, false);
        entry.update_fields(MemoryAttributes::empty(), PhysicalAddress::new(0), true)?;
        entry.set_present(false);
        pt.zero_va_pt_pa = Some(table_base);

        Ok(pt)
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
        Arch::paging_type_supported(paging_type)?;

        let base = PhysicalAddress::new(base);
        if !base.is_page_aligned() {
            return Err(PtError::UnalignedPageBase);
        }

        Ok(Self { base, page_allocator, paging_type, zero_va_pt_pa: None, _arch: PhantomData })
    }

    /// Function to borrow the allocator from the page table instance.
    /// This is done this way to allow the page table to return a concrete
    /// type instead of the dyn ref. This is required to allow the page allocator to
    /// be managed by the caller, while the page table can still allocate pages from
    /// the allocator
    ///
    /// ## Returns
    /// * `&mut Self::ALLOCATOR` - Borrowed allocator
    pub fn borrow_allocator(&mut self) -> &mut P {
        &mut self.page_allocator
    }

    /// Consumes the page table structure and returns the page table root.
    pub fn into_page_table_root(self) -> u64 {
        self.base.into()
    }

    pub fn allocate_page(&mut self) -> PtResult<PhysicalAddress> {
        let base = self.page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, false)?;

        // SAFETY: We just allocated the page, so it is safe to use it.
        // We always need to zero any pages, as our contract with the page_allocator does not specify that we will
        // get zeroed pages. Random data in the page could confuse this code and make us believe there are existing
        // entries in the page table.
        let zero_va = match self.is_installed_and_self_mapped() {
            true => {
                let va = Arch::get_zero_va(self.paging_type)?;

                // we don't actually need this currently, but if it isn't set and we think the self map is set up,
                // something has gone very wrong
                let zero_va_pt_pa = match self.zero_va_pt_pa {
                    Some(pa) => pa,
                    _ => return Err(PtError::InvalidParameter),
                };

                // if we have set up the zero VA, we need to map the PA we just allocated into this range to zero it
                // as we are relying on the self map to map these pages and we want to ensure break before make
                // semantics.
                // the page_base doesn't matter here because we don't use it in self-map mode, but let's still set
                // the right address in case it gets used in the future and it is easy to persist
                let mut zero_entry = Arch::PTE::new(zero_va_pt_pa, 0, PageLevel::Level1, self.paging_type, va, true);

                zero_entry.update_fields(
                    MemoryAttributes::empty() | MemoryAttributes::ExecuteProtect,
                    PhysicalAddress::new(base),
                    true,
                )?;

                Arch::invalidate_tlb(Some(va));

                va
            }
            // If we have not installed this page table, we can't use our VA range to zero pages yet and have to go on
            // the assumption that the caller has this page mapped
            false => base.into(),
        };

        unsafe { Arch::zero_page(zero_va.into()) };
        let base = PhysicalAddress::new(base);
        if !base.is_page_aligned() {
            return Err(PtError::UnalignedPageBase);
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

        let table =
            Table::<Arch>::new(base, level, start_va, end_va, self.paging_type, self.is_installed_and_self_mapped());

        for mut entry in table {
            if !entry.present()
                && entry.supports_pa_entry()
                && va.is_level_aligned(level)
                && va.length_through(end_va) >= level.entry_va_size()
            {
                // This entry is large enough to be a whole entry for this supporting level,
                // so we can map the whole range in one go.
                entry.update_fields(attributes, va.into(), true)?;
            } else {
                let next_level = match level.next_level() {
                    Some(next_level) => next_level,
                    None => {
                        // We are trying to map a page but it is already mapped. The caller has an inconsistent state
                        // of the page table
                        log::error!(
                            "Paging crate failed to map memory region at VA {:#x?} as the entry is already valid",
                            va
                        );
                        return Err(PtError::InconsistentMappingAcrossRange);
                    }
                };

                if !entry.present() {
                    let pa = self.allocate_page()?;
                    // non-leaf pages should always have the most permissive memory attributes.
                    entry.update_fields(MemoryAttributes::empty(), pa, false)?;
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
                    next_level,
                    next_base,
                    attributes,
                )?;
            }

            va = va.get_next_va(level);
        }

        Ok(())
    }

    fn unmap_memory_region_internal(
        &mut self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
    ) -> PtResult<()> {
        let mut va = start_va;

        let table =
            Table::<Arch>::new(base, level, start_va, end_va, self.paging_type, self.is_installed_and_self_mapped());

        for mut entry in table {
            // Check if this is a large page in need of splitting.
            if entry.points_to_pa()
                && (!va.is_level_aligned(level) || va.length_through(end_va) < level.entry_va_size())
            {
                self.split_large_page(va, &mut entry)?;
            }

            // This is at least either the entirety of a large page or a single page.
            if entry.present() {
                if entry.points_to_pa() {
                    entry.set_present(false);
                } else {
                    let next_level = level.next_level().unwrap();
                    let next_base = entry.get_canonical_page_table_base();

                    // split the va range appropriately for the next level pages

                    // start of the next level va. It will be same as current va
                    let next_level_start_va = va;

                    // get max va addressable by current entry
                    let curr_va_ceil = va.round_up(level);

                    // end of next level va. It will be minimum of next va and end va
                    let next_level_end_va = VirtualAddress::min(curr_va_ceil, end_va);

                    self.unmap_memory_region_internal(next_level_start_va, next_level_end_va, next_level, next_base)?;
                }
            }
            va = va.get_next_va(level);
        }

        Ok(())
    }

    fn remap_memory_region_internal(
        &mut self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
        attributes: MemoryAttributes,
    ) -> PtResult<()> {
        let mut va = start_va;

        let table =
            Table::<Arch>::new(base, level, start_va, end_va, self.paging_type, self.is_installed_and_self_mapped());

        for mut entry in table {
            if !entry.present() {
                return Err(PtError::NoMapping);
            }

            // Check if this is a large page in need of splitting.
            if entry.points_to_pa()
                && (!va.is_level_aligned(level) || va.length_through(end_va) < level.entry_va_size())
            {
                self.split_large_page(va, &mut entry)?;
            }

            if entry.points_to_pa() {
                entry.update_fields(attributes, va.into(), true)?;
            } else {
                let next_level = level.next_level().unwrap();
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
                    next_level,
                    next_base,
                    attributes,
                )?;
            }

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
        prev_attributes: &mut RangeMappingState,
    ) -> PtResult<MemoryAttributes> {
        let mut va = start_va;

        let table =
            Table::<Arch>::new(base, level, start_va, end_va, self.paging_type, self.is_installed_and_self_mapped());
        let mut entries = table.into_iter().peekable();
        while let Some(entry) = entries.next() {
            if !entry.present() {
                // if we found an entry that is not present after finding entries that were already mapped,
                // we fail this with InconsistentMappingAcrossRange. If we have set found any region yet, mark
                // this as an unmapped region and continue
                match prev_attributes {
                    RangeMappingState::Uninitialized => *prev_attributes = RangeMappingState::Unmapped,
                    RangeMappingState::Mapped(_) => return Err(PtError::InconsistentMappingAcrossRange),
                    RangeMappingState::Unmapped => {}
                }
                continue;
            }

            if entry.points_to_pa() {
                let current_attributes = entry.get_attributes();
                match prev_attributes {
                    RangeMappingState::Uninitialized => {
                        *prev_attributes = RangeMappingState::Mapped(current_attributes)
                    }
                    RangeMappingState::Unmapped => return Err(PtError::InconsistentMappingAcrossRange),
                    RangeMappingState::Mapped(attrs) => {
                        if *attrs != current_attributes {
                            return Err(PtError::IncompatibleMemoryAttributes);
                        }
                    }
                }
            } else {
                let next_level = level.next_level().unwrap();
                let next_base = entry.get_canonical_page_table_base();

                // split the va range appropriately for the next level pages

                // start of the next level va. It will be same as current va
                let next_level_start_va = va;

                // get max va addressable by current entry
                let curr_va_ceil = va.round_up(level);

                // end of next level va. It will be minimum of next va and end va
                let next_level_end_va = VirtualAddress::min(curr_va_ceil, end_va);

                // if we got an error besides NoMapping, we should return that up the stack, we've failed entirely
                // no mapping may be the case, but we need to continue walking down the page tables to see if we
                // find any mapped regions and need to fail the query with InconsistentMappingAcrossRange
                match self.query_memory_region_internal(
                    next_level_start_va,
                    next_level_end_va,
                    next_level,
                    next_base,
                    prev_attributes,
                ) {
                    Ok(_) | Err(PtError::NoMapping) => {}
                    Err(e) => return Err(e),
                }
            }

            // only calculate the next VA if there is another entry in the table we are processing
            // when processing the self map, always calculating the next VA can result in overflow needlessly
            if entries.peek().is_some() {
                va = va.get_next_va(level);
            }
        }

        match prev_attributes {
            // entire region was mapped consistently
            RangeMappingState::Mapped(attrs) => Ok(*attrs),
            // we only found unmapped regions, so report the entire region is unmapped
            _ => Err(PtError::NoMapping),
        }
    }

    /// Splits a large page into the next page level pages. This done by
    /// creating a new page table for the full range and then swapping the PA
    /// and mapping to the new page table.
    fn split_large_page(&mut self, va: VirtualAddress, entry: &mut Arch::PTE) -> PtResult<()> {
        let level = entry.get_level();
        let next_level = level.next_level().unwrap();
        debug_assert!(entry.points_to_pa());

        // Round down to the nearest page boundary at the current level.
        let large_page_start: u64 = va.into();
        let large_page_start = large_page_start & !(level.entry_va_size() - 1);
        let large_page_end: u64 = large_page_start + level.entry_va_size() - 1;

        if !entry.points_to_pa() {
            return Err(PtError::InvalidParameter);
        }

        let attributes = entry.get_attributes();
        let pa = self.allocate_page()?;

        // in order to use the self map, we have to add the PA to the page table, otherwise it is not part of
        // the self map. This means we will temporarily unmap the large page entry that was here, but as soon as
        // we complete map_memory_region_internal, it will be mapped at the new level. This is safe because the
        // paging code only references self map addresses, which are not large pages. The currently executing code
        // will also not be mapped as large pages. There is a small possibility that when a new page is allocated
        // for a lower level, the allocator code will try to reference this formerly mapped large page, but this is
        // not a likely scenario. We do not need to invalidate the TLB here, because this is a new mapping with a
        // unique address in the self map that has not been referenced before. We do invalidate the TLB after finishing
        // whichever operation called this function.
        entry.update_fields(MemoryAttributes::empty(), pa, false)?;

        // invalidate the self map VA for the region covered by the large page
        // this function gets called multiple times to split from larger pages to smaller pages, so we only invalidate
        // once for the new page table we created
        let table =
            Table::<Arch>::new(pa, next_level, large_page_start.into(), large_page_end.into(), self.paging_type, true);

        if let Some(tb_entry) = table.into_iter().next() {
            Arch::invalidate_tlb(Some(tb_entry.raw_address().into()));
        }

        self.map_memory_region_internal(large_page_start.into(), large_page_end.into(), next_level, pa, attributes)
    }

    fn dump_page_tables_internal(
        &self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
    ) {
        todo!();
    }

    fn validate_address_range(&self, address: VirtualAddress, size: u64) -> PtResult<()> {
        if size == 0 {
            return Err(PtError::InvalidMemoryRange);
        }

        let max_va = Arch::get_max_va(self.paging_type)?;

        // Overflow check, size is 0-based
        let top_va = address.try_add(size - 1)?;
        if top_va > max_va {
            return Err(PtError::InvalidMemoryRange);
        }

        if !max_va.is_page_aligned() {
            return Err(PtError::UnalignedAddress);
        }

        if !VirtualAddress::new(size).is_page_aligned() {
            return Err(PtError::UnalignedMemoryRange);
        }

        Ok(())
    }

    /// Check if the page table is installed and self-mapped.
    /// This is used to determine if we can use the self-map to zero pages and reference the page table pages.
    /// If our page table base is not in cr3, self-mapped entries won't work for this page table. Similarly, if the
    /// expected self-map entry is not present or does not point to the page table base, we can't use the self-map.
    fn is_installed_and_self_mapped(&self) -> bool {
        if !Arch::is_table_active(self.base.into()) {
            return false;
        }

        // this is always read from the physical address of the page table, because we are trying to determine whether
        // we are self-mapped or not
        let self_map_entry = Arch::PTE::new(
            self.base,
            SELF_MAP_INDEX,
            self.paging_type.root_level(),
            self.paging_type,
            self.base.into(),
            false,
        );

        if !self_map_entry.present() || self_map_entry.get_canonical_page_table_base() != self.base {
            return false;
        }

        true
    }

    pub fn map_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        // We map until next alignment
        let start_va = address;
        let end_va = address + size - 1;

        let result =
            self.map_memory_region_internal(start_va, end_va, self.paging_type.root_level(), self.base, attributes);

        if Arch::is_table_active(self.base.into()) {
            Arch::invalidate_tlb(None);
        }

        result
    }

    pub fn unmap_memory_region(&mut self, address: u64, size: u64) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + size - 1;

        let result = self.unmap_memory_region_internal(start_va, end_va, self.paging_type.root_level(), self.base);

        if Arch::is_table_active(self.base.into()) {
            Arch::invalidate_tlb(None);
        }

        result
    }

    pub fn remap_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + size - 1;

        // make sure the memory region has same attributes set
        let mut prev_attributes = RangeMappingState::Uninitialized;
        self.query_memory_region_internal(
            start_va,
            end_va,
            self.paging_type.root_level(),
            self.base,
            &mut prev_attributes,
        )?;

        let result =
            self.remap_memory_region_internal(start_va, end_va, self.paging_type.root_level(), self.base, attributes);

        if Arch::is_table_active(self.base.into()) {
            Arch::invalidate_tlb(None);
        }

        result
    }

    pub fn install_page_table(&mut self) -> PtResult<()> {
        // The page table structure should guarantee that the page table is correct.
        unsafe { Arch::install_page_table(self.base.into()) }
    }

    pub fn query_memory_region(&self, address: u64, size: u64) -> PtResult<MemoryAttributes> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + (size - 1);

        let mut prev_attributes = RangeMappingState::Uninitialized;
        self.query_memory_region_internal(
            start_va,
            end_va,
            self.paging_type.root_level(),
            self.base,
            &mut prev_attributes,
        )
    }

    pub fn dump_page_tables(&self, address: u64, size: u64) {
        todo!();
    }
}

struct Table<Arch: PageTableArch> {
    /// Physical page table base address
    base: PhysicalAddress,

    /// Page table's page level
    level: PageLevel,

    /// Start of the virtual address manageable by this page table
    start_va: VirtualAddress,

    /// End of the virtual address manageable by this page table
    end_va: VirtualAddress,

    /// Paging type of the page table
    paging_type: PagingType,

    /// Whether the page table is installed and self-mapped
    installed_and_self_mapped: bool,

    _arch: PhantomData<Arch>,
}

impl<Arch: PageTableArch> Table<Arch> {
    pub fn new(
        base: PhysicalAddress,
        level: PageLevel,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        paging_type: PagingType,
        installed_and_self_mapped: bool,
    ) -> Self {
        Self { base, level, start_va, end_va, paging_type, installed_and_self_mapped, _arch: PhantomData }
    }
}

impl<Arch: PageTableArch> IntoIterator for Table<Arch> {
    type Item = Arch::PTE;

    type IntoIter = TableIterator<Arch>;

    fn into_iter(self) -> Self::IntoIter {
        TableIterator::<Arch> {
            level: self.level,
            start_index: self.start_va.get_index(self.level),
            end_index: self.end_va.get_index(self.level),
            base: self.base,
            start_va: self.start_va,
            paging_type: self.paging_type,
            installed_and_self_mapped: self.installed_and_self_mapped,
            _arch: PhantomData,
        }
    }
}

struct TableIterator<Arch: PageTableArch> {
    level: PageLevel,
    start_index: u64,
    end_index: u64,
    base: PhysicalAddress,
    start_va: VirtualAddress,
    paging_type: PagingType,
    installed_and_self_mapped: bool,
    _arch: PhantomData<Arch>,
}

impl<Arch: PageTableArch> Iterator for TableIterator<Arch> {
    type Item = Arch::PTE;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start_index <= self.end_index {
            let index = self.start_index;
            self.start_index += 1;
            Some(Arch::PTE::new(
                self.base,
                index,
                self.level,
                self.paging_type,
                self.start_va,
                self.installed_and_self_mapped,
            ))
        } else {
            None
        }
    }
}
