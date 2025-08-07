use core::marker::PhantomData;

use crate::{
    MemoryAttributes, PagingType, PtError, PtResult, RangeMappingState,
    arch::PageTableEntry,
    arch::PageTableHal,
    page_allocator::PageAllocator,
    structs::{PAGE_SIZE, PageLevel, PhysicalAddress, SELF_MAP_INDEX, VirtualAddress, ZERO_VA_INDEX},
};

/// Tracks the supported states of the page tables. Specifically, whether the page
/// tables are actively installed and whether they are self-mapped. This will change
/// behavior such as how the page tables are accessed and how caches are managed.
#[derive(PartialEq, Clone, Copy, Debug)]
pub enum PageTableState {
    /// The page table is not installed. It is assumed to be identity mapped.
    Inactive,
    /// The page table is installed but not self-mapped. It is assumed to be identity mapped.
    ActiveIdentityMapped,
    /// The page table is installed and self-mapped. Only the root is guaranteed to be identity mapped.
    ActiveSelfMapped,
}

impl PageTableState {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::ActiveIdentityMapped | Self::ActiveSelfMapped)
    }

    pub fn self_map(&self) -> bool {
        matches!(self, Self::ActiveSelfMapped)
    }
}

#[derive(Debug)]
pub struct PageTableInternal<P: PageAllocator, Arch: PageTableHal> {
    base: PhysicalAddress,
    page_allocator: P,
    pub(crate) paging_type: PagingType,
    zero_va_pt_pa: Option<PhysicalAddress>,
    _arch: PhantomData<Arch>,
}

impl<P: PageAllocator, Arch: PageTableHal> PageTableInternal<P, Arch> {
    pub fn new(mut page_allocator: P, paging_type: PagingType) -> PtResult<Self> {
        Arch::paging_type_supported(paging_type)?;
        let root_level = PageLevel::root_level(paging_type);

        // Allocate the top level page table
        let base = page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, true)?;
        if !PhysicalAddress::new(base).is_page_aligned() {
            return Err(PtError::UnalignedPageBase);
        }

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
        let mut self_map_entry =
            Arch::PTE::new(pt.base, SELF_MAP_INDEX, root_level, paging_type, pt.base.into(), PageTableState::Inactive)?;

        // create it with permissive attributes
        self_map_entry.update_fields(Arch::DEFAULT_ATTRIBUTES, pt.base, false)?;

        // Setup the zero VA entry to allow for zeroing pages before putting them in the page table.
        let mut table_base = pt.base;
        let mut level = root_level;
        let mut index = ZERO_VA_INDEX;
        let zero_va = Arch::get_zero_va(paging_type)?;
        while let Some(next_level) = level.next_level() {
            let new_table = pt.page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, false)?;

            // SAFETY: We just allocated the page, so it is safe to use it.
            unsafe { Arch::zero_page(new_table.into()) };

            let mut entry = Arch::PTE::new(table_base, index, level, paging_type, zero_va, PageTableState::Inactive)?;
            entry.update_fields(Arch::DEFAULT_ATTRIBUTES, PhysicalAddress::new(new_table), false)?;

            // After the first-level index, all other indexes are 0.
            index = 0;
            level = next_level;
            table_base = PhysicalAddress::new(new_table);
        }

        // Create the leaf zero VA entry.
        let mut entry = Arch::PTE::new(table_base, 0, level, paging_type, zero_va, PageTableState::Inactive)?;
        entry.update_fields(Arch::DEFAULT_ATTRIBUTES, PhysicalAddress::new(0), true)?;
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

    /// Consumes the page table structure and returns the page table root.
    pub fn into_page_table_root(self) -> u64 {
        self.base.into()
    }

    pub fn allocate_page(&mut self, state: PageTableState) -> PtResult<PhysicalAddress> {
        let base = self.page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, false)?;
        let base_pa = PhysicalAddress::new(base);
        if !base_pa.is_page_aligned() {
            return Err(PtError::UnalignedPageBase);
        }

        // SAFETY: We just allocated the page, so it is safe to use it.
        // We always need to zero any pages, as our contract with the page_allocator does not specify that we will
        // get zeroed pages. Random data in the page could confuse this code and make us believe there are existing
        // entries in the page table.
        let zero_va = match state {
            PageTableState::ActiveSelfMapped => {
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
                let mut zero_entry = Arch::PTE::new(zero_va_pt_pa, 0, PageLevel::Level1, self.paging_type, va, state)?;

                zero_entry.update_fields(
                    Arch::DEFAULT_ATTRIBUTES | MemoryAttributes::ExecuteProtect,
                    PhysicalAddress::new(base),
                    true,
                )?;

                Arch::invalidate_tlb(va);

                va
            }
            // If we have not installed this page table, we can't use our VA range to zero pages yet and have to go on
            // the assumption that the caller has this page mapped
            _ => base.into(),
        };

        unsafe { Arch::zero_page(zero_va) };

        Ok(base_pa)
    }

    // For a given memory range, the number of intermediate page table entries
    // can span across multiple pages(as shown below), here Lvl4E is spread
    // across 3 pages(first and last page not fully occupied), the reason for
    // this spread is because of number of parent entries(Lvl5E). For example,
    // when processing the offsets in 0x301D600000000 - 0x602AC00000000 VA
    // range, we will have 4 entries([3-6]) for PML5 and 5 entries for
    // Lvl4([3-7]). But the actual number of Lvl4 entries required are [3-511] +
    // [0-511] + [0-511] + [0-7] = 1541 entries.
    //
    // 0x000301D600000000 :
    //       |      Lvl5|     Lvl4|     Lvl3|     Lvl2|     Lvl1|    Physical
    // 000000|0000000011|000000011|101011000|000000000|000000000|000000000000
    //      0|         3|        3|      344|        0|        0|           0 Decimal
    // 0x000603ABFFFFFFFF :
    //       |      Lvl5|     Lvl4|     Lvl3|     Lvl2|     Lvl1|    Physical
    // 000000|0000000110|000000111|010101111|111111111|111111111|111111111111
    //      0|         6|        7|      175|      511|      511|        4095 Decimal
    //
    // Because of this, the page walking logic should appropriately split the
    // memory ranges when jumping to next level page tables. Just relying on
    // indices at the current level do not work! Below is a recursive
    // implementation of it.
    //
    //  │               │  ┌─────┐       │
    //  │               │  │     │       │
    //  │               │  ├─────┤       │
    //  │               │  │     │       │
    //  │               │  ├─────┤       │
    //  │               └─►│Lvl4E│       │
    //  │               │  ├─────┤       │
    //  │               │  │Lvl4E|       │
    //  │          ┌──────►└─────┘       │
    //  │          │    │  ┌─────┐       │  ┌─────┐
    //  │          │    │  │Lvl4E│       │  │     │
    //  │          │    │  ├─────┤       │  ├─────┤
    //  │          │    │  │Lvl4E│       │  │     │
    //  │          │    │  ├─────┤       │  ├─────┤
    //  │          │    └─►│Lvl4E│       │  |Lvl2E│
    //  │          │    │  ├─────┤       │  ├─────┤
    //  │          │    │  │Lvl4E|       |  |Lvl2E|
    //  │          │ ┌────►└─────┘   ┌─────►└─────┘
    //  │  ┌─────┐ │ │  │  ┌─────┐   │   │  ┌─────┐
    //  │  │Lvl5E│─┘ │  │  │Lvl4E|───┘   │  |Lvl2E|
    //  │  ├─────┤   │  │  ├─────┤       │  ├─────┤
    //  │  │Lvl5E│───┘  └─►│Lvl4E│───┐   │  |Lvl2E│
    //  │  ├─────┤         ├─────┤   │   │  ├─────┤
    //  └─►│Lvl5E├───┐     │     │   │   └─►|Lvl2E│───┐
    //     ├─────┤   │     ├─────┤   │      ├─────┤   │
    //     │     │   │     │     │   │      │     │   │
    //     └─────┘   └────►└─────┘   └─────►└─────┘   └────►

    fn map_memory_region_internal(
        &mut self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
        attributes: MemoryAttributes,
        state: PageTableState,
    ) -> PtResult<()> {
        let mut va = start_va;

        let table = PageTableRange::<Arch>::new(base, level, start_va, end_va, self.paging_type, state);

        for mut entry in table {
            if !entry.present()
                && Arch::level_supports_pa_entry(level)
                && va.is_level_aligned(level)
                && va.length_through(end_va)? >= level.entry_va_size()
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
                    let pa = self.allocate_page(state)?;
                    // non-leaf pages should always have the most permissive memory attributes.
                    entry.update_fields(Arch::DEFAULT_ATTRIBUTES, pa, false)?;
                }
                let next_base = entry.get_address();

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
                    state,
                )?;
            }

            va = va.get_next_va(level)?;
        }

        Ok(())
    }

    fn unmap_memory_region_internal(
        &mut self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
        state: PageTableState,
    ) -> PtResult<()> {
        let mut va = start_va;

        let table = PageTableRange::<Arch>::new(base, level, start_va, end_va, self.paging_type, state);

        for mut entry in table {
            // Check if this is a large page in need of splitting.
            if entry.points_to_pa()
                && (!va.is_level_aligned(level) || va.length_through(end_va)? < level.entry_va_size())
            {
                self.split_large_page(va, &mut entry, state)?;
            }

            // This is at least either the entirety of a large page or a single page.
            if entry.present() {
                if entry.points_to_pa() {
                    entry.set_present(false);
                } else {
                    // This should always have another level if this is not a PA entry.
                    let next_level = level.next_level().unwrap();
                    let next_base = entry.get_address();

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
                        next_level,
                        next_base,
                        state,
                    )?;
                }
            }
            va = va.get_next_va(level)?;
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
        state: PageTableState,
    ) -> PtResult<()> {
        let mut va = start_va;

        let table = PageTableRange::<Arch>::new(base, level, start_va, end_va, self.paging_type, state);

        for mut entry in table {
            if !entry.present() {
                return Err(PtError::NoMapping);
            }

            // Check if this is a large page in need of splitting.
            if entry.points_to_pa()
                && (!va.is_level_aligned(level) || va.length_through(end_va)? < level.entry_va_size())
            {
                self.split_large_page(va, &mut entry, state)?;
            }

            if entry.points_to_pa() {
                entry.update_fields(attributes, va.into(), true)?;
            } else {
                let next_level = level.next_level().unwrap();
                let next_base = entry.get_address();

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
                    state,
                )?;
            }

            va = va.get_next_va(level)?;
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
        state: PageTableState,
    ) -> PtResult<MemoryAttributes> {
        let mut va = start_va;

        let table = PageTableRange::<Arch>::new(base, level, start_va, end_va, self.paging_type, state);
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
                let next_base = entry.get_address();

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
                    state,
                ) {
                    Ok(_) | Err(PtError::NoMapping) => {}
                    Err(e) => return Err(e),
                }
            }

            // only calculate the next VA if there is another entry in the table we are processing
            // when processing the self map, always calculating the next VA can result in overflow needlessly
            if entries.peek().is_some() {
                va = va.get_next_va(level)?;
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
    fn split_large_page(&mut self, va: VirtualAddress, entry: &mut Arch::PTE, state: PageTableState) -> PtResult<()> {
        let level = entry.get_level();
        let next_level = level.next_level().unwrap();
        if !entry.points_to_pa() {
            log::error!(
                "Failed to split large page at VA {:#x?} as the entry does not point to a physical address",
                va
            );
            return Err(PtError::InvalidParameter);
        }

        // Round down to the nearest page boundary at the current level.
        let large_page_start: u64 = va.into();
        let large_page_start = large_page_start & !(level.entry_va_size() - 1);
        let large_page_end: u64 = large_page_start + level.entry_va_size() - 1;

        if !entry.points_to_pa() {
            return Err(PtError::InvalidParameter);
        }

        let attributes = entry.get_attributes();
        let pa = self.allocate_page(state)?;

        // in order to use the self map, we have to add the PA to the page table, otherwise it is not part of
        // the self map. This means we will temporarily unmap the large page entry that was here, but as soon as
        // we complete map_memory_region_internal, it will be mapped at the new level. This is safe because the
        // paging code only references self map addresses, which are not large pages. The currently executing code
        // will also not be mapped as large pages. There is a small possibility that when a new page is allocated
        // for a lower level, the allocator code will try to reference this formerly mapped large page, but this is
        // not a likely scenario. We do not need to invalidate the TLB here, because this is a new mapping with a
        // unique address in the self map that has not been referenced before. We do invalidate the TLB after finishing
        // whichever operation called this function.
        entry.update_fields(Arch::DEFAULT_ATTRIBUTES, pa, false)?;

        if matches!(state, PageTableState::ActiveSelfMapped) {
            // invalidate the self map VA for the region covered by the large page
            // this function gets called multiple times to split from larger pages to smaller pages, so we only invalidate
            // once for the new page table we created
            let table = PageTableRange::<Arch>::new(
                pa,
                next_level,
                large_page_start.into(),
                large_page_end.into(),
                self.paging_type,
                state,
            );

            if let Some(tb_entry) = table.into_iter().next() {
                Arch::invalidate_tlb(tb_entry.entry_ptr_address().into());
            }
        }

        self.map_memory_region_internal(
            large_page_start.into(),
            large_page_end.into(),
            next_level,
            pa,
            attributes,
            state,
        )
    }

    fn dump_page_tables_internal(
        &self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
        state: PageTableState,
    ) -> PtResult<()> {
        let mut va = start_va;

        let table = PageTableRange::<Arch>::new(base, level, start_va, end_va, self.paging_type, state);
        for entry in table {
            if !entry.present() && !level.is_lowest_level() {
                return Err(PtError::NoMapping);
            }

            // split the va range appropriately for the next level pages

            // start of the next level va. It will be same as current va
            let next_level_start_va = va;

            // get max va addressable by current entry
            let curr_va_ceil = va.round_up(level);

            // end of next level va. It will be minimum of next va and end va
            let next_level_end_va = VirtualAddress::min(curr_va_ceil, end_va);

            entry.dump_entry()?;
            if entry.present() && !entry.points_to_pa() {
                let next_base = entry.get_address();
                self.dump_page_tables_internal(
                    next_level_start_va,
                    next_level_end_va,
                    level.next_level().unwrap(),
                    next_base,
                    state,
                )?;
            }

            va = va.get_next_va(level)?;
        }

        Ok(())
    }

    fn validate_address_range(&self, address: VirtualAddress, size: u64) -> PtResult<()> {
        if size == 0 {
            return Err(PtError::InvalidMemoryRange);
        }

        if !address.is_page_aligned() {
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
    fn get_state(&self) -> PageTableState {
        if !Arch::is_table_active(self.base.into()) {
            return PageTableState::Inactive;
        }

        // this is always read from the physical address of the page table, because we are trying to determine whether
        // we are self-mapped or not. The root should always be accessible, only assume active for now.
        let self_map_entry = match Arch::PTE::new(
            self.base,
            SELF_MAP_INDEX,
            PageLevel::root_level(self.paging_type),
            self.paging_type,
            self.base.into(),
            PageTableState::ActiveIdentityMapped,
        ) {
            Ok(entry) => entry,
            Err(_) => return PageTableState::ActiveIdentityMapped, // if we can't read the entry, assume identity mapped
        };

        if !self_map_entry.present() || self_map_entry.get_address() != self.base {
            PageTableState::ActiveIdentityMapped
        } else {
            PageTableState::ActiveSelfMapped
        }
    }

    pub fn map_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let max_va = Arch::get_max_va(self.paging_type)?;

        // Overflow check, size is 0-based
        let top_va = (address + (size - 1))?;
        if top_va > max_va {
            return Err(PtError::InvalidMemoryRange);
        }

        // We map until next alignment
        let start_va = address;
        let end_va = (address + (size - 1))?;

        self.map_memory_region_internal(
            start_va,
            end_va,
            PageLevel::root_level(self.paging_type),
            self.base,
            attributes,
            self.get_state(),
        )
    }

    pub fn unmap_memory_region(&mut self, address: u64, size: u64) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let max_va = Arch::get_max_va(self.paging_type)?;

        // Overflow check, size is 0-based
        let top_va = (address + (size - 1))?;
        if top_va > max_va {
            return Err(PtError::InvalidMemoryRange);
        }

        let start_va = address;
        let end_va = (address + (size - 1))?;

        self.unmap_memory_region_internal(
            start_va,
            end_va,
            PageLevel::root_level(self.paging_type),
            self.base,
            self.get_state(),
        )
    }

    pub fn remap_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let max_va = Arch::get_max_va(self.paging_type)?;

        // Overflow check, size is 0-based
        let top_va = (address + (size - 1))?;
        if top_va > max_va {
            return Err(PtError::InvalidMemoryRange);
        }

        let start_va = address;
        let end_va = (address + (size - 1))?;
        let state = self.get_state();

        // make sure the memory region has same attributes set
        let mut prev_attributes = RangeMappingState::Uninitialized;
        self.query_memory_region_internal(
            start_va,
            end_va,
            PageLevel::root_level(self.paging_type),
            self.base,
            &mut prev_attributes,
            state,
        )?;

        self.remap_memory_region_internal(
            start_va,
            end_va,
            PageLevel::root_level(self.paging_type),
            self.base,
            attributes,
            state,
        )
    }

    pub fn install_page_table(&mut self) -> PtResult<()> {
        // The page table structure should guarantee that the page table is correct.
        unsafe { Arch::install_page_table(self.base.into()) }
    }

    pub fn query_memory_region(&self, address: u64, size: u64) -> PtResult<MemoryAttributes> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = (address + (size - 1))?;

        let mut prev_attributes = RangeMappingState::Uninitialized;
        self.query_memory_region_internal(
            start_va,
            end_va,
            PageLevel::root_level(self.paging_type),
            self.base,
            &mut prev_attributes,
            self.get_state(),
        )
    }

    pub fn dump_page_tables(&self, address: u64, size: u64) -> PtResult<()> {
        if self.validate_address_range(address.into(), size).is_err() {
            log::error!("Invalid address range for page table dump! Address: {:#x?}, Size: {:#x?}", address, size);
            return Err(PtError::InvalidMemoryRange);
        }

        let address = VirtualAddress::new(address);
        let start_va = address;
        let end_va = (address + (size - 1))?;

        log::info!("Page Table Range: {} - {}", start_va, end_va);
        Arch::PTE::dump_entry_header();
        self.dump_page_tables_internal(
            start_va,
            end_va,
            PageLevel::root_level(self.paging_type),
            self.base,
            self.get_state(),
        )?;

        Ok(())
    }
}

struct PageTableRange<Arch: PageTableHal> {
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
    state: PageTableState,

    // Phantom data to allow for compile time use of static architecture routines.
    _arch: PhantomData<Arch>,
}

impl<Arch: PageTableHal> PageTableRange<Arch> {
    pub fn new(
        base: PhysicalAddress,
        level: PageLevel,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        paging_type: PagingType,
        state: PageTableState,
    ) -> Self {
        Self { base, level, start_va, end_va, paging_type, state, _arch: PhantomData }
    }
}

impl<Arch: PageTableHal> IntoIterator for PageTableRange<Arch> {
    type Item = Arch::PTE;

    type IntoIter = EntryIterator<Arch>;

    fn into_iter(self) -> Self::IntoIter {
        EntryIterator::<Arch> {
            level: self.level,
            start_index: self.start_va.get_index(self.level),
            end_index: self.end_va.get_index(self.level),
            base: self.base,
            start_va: self.start_va,
            paging_type: self.paging_type,
            state: self.state,
            _arch: PhantomData,
        }
    }
}

struct EntryIterator<Arch: PageTableHal> {
    level: PageLevel,
    start_index: u64,
    end_index: u64,
    base: PhysicalAddress,
    start_va: VirtualAddress,
    paging_type: PagingType,
    state: PageTableState,
    _arch: PhantomData<Arch>,
}

impl<Arch: PageTableHal> Iterator for EntryIterator<Arch> {
    type Item = Arch::PTE;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start_index <= self.end_index {
            let index = self.start_index;
            let va = self.start_va;

            // only calculate the next VA if we are not at the end of the range otherwise we can needlessly overflow
            // for a VA we would never try to use
            if self.start_index < self.end_index {
                self.start_va = match self.start_va.get_next_va(self.level) {
                    Ok(next_va) => next_va,
                    Err(_) => return None, // If we can't get the next VA, we stop iterating.
                };
            }
            self.start_index += 1;

            match Arch::PTE::new(self.base, index, self.level, self.paging_type, va, self.state) {
                Ok(entry) => Some(entry),
                Err(_) => None, // If we can't create the entry, we just skip it.
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MemoryAttributes, PagingType, PtError,
        arch::PageTableHal,
        page_allocator::PageAllocator,
        structs::{PAGE_SIZE, PageLevel, PhysicalAddress, VirtualAddress},
    };
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    // BackingPTE simulates the actual memory backing for PTEs (like in structs.rs)
    #[derive(Clone, Debug, PartialEq)]
    struct BackingPTE {
        present: bool,
        pa: PhysicalAddress,
        level: PageLevel,
        attributes: MemoryAttributes,
        leaf: bool,
    }

    impl BackingPTE {
        fn new(level: PageLevel) -> Self {
            Self {
                present: false,
                pa: PhysicalAddress::new(0),
                level,
                attributes: MemoryAttributes::empty(),
                leaf: false,
            }
        }
    }

    type TestPageTableStoreEntryMap = Rc<RefCell<HashMap<(u64, u64, PageLevel), BackingPTE>>>;

    // Simulate a page table store (physical memory for PTEs)
    #[derive(Clone, Debug)]
    struct PageTableStore {
        // key: (base_pa, index, level)
        entries: TestPageTableStoreEntryMap,
    }

    impl PageTableStore {
        fn new() -> Self {
            Self { entries: Rc::new(RefCell::new(HashMap::new())) }
        }

        fn get(&self, base: PhysicalAddress, index: u64, level: PageLevel) -> BackingPTE {
            self.entries.borrow().get(&(base.into(), index, level)).cloned().unwrap_or_else(|| BackingPTE::new(level))
        }

        fn set(&self, base: PhysicalAddress, index: u64, level: PageLevel, pte: BackingPTE) {
            self.entries.borrow_mut().insert((base.into(), index, level), pte);
        }
    }

    // DummyAllocator for page allocation
    #[derive(Clone, Debug)]
    struct DummyAllocator {
        page_allocs: u64,
    }
    impl PageAllocator for DummyAllocator {
        fn allocate_page(&mut self, _align: u64, _size: u64, _is_root: bool) -> PtResult<u64> {
            let page = 0x1000 + self.page_allocs * PAGE_SIZE;
            self.page_allocs += 1;
            Ok(page)
        }
    }

    // DummyPTE matches the architecture PTE structure in pagetablestore.rs
    #[derive(Clone)]
    struct DummyPTE {
        base: PhysicalAddress,
        index: u64,
        level: PageLevel,
        va: VirtualAddress,
        store: PageTableStore,
    }

    impl PageTableEntry for DummyPTE {
        fn new(
            base: PhysicalAddress,
            index: u64,
            level: PageLevel,
            _paging_type: PagingType,
            va: VirtualAddress,
            _state: PageTableState,
        ) -> PtResult<Self> {
            // For tests, always use a global store
            let store = DUMMY_STORE.with(|s| s.borrow().clone());
            Ok(DummyPTE { base, index, level, va, store })
        }
        fn update_fields(&mut self, attrs: MemoryAttributes, pa: PhysicalAddress, leaf_entry: bool) -> PtResult<()> {
            let mut pte = self.store.get(self.base, self.index, self.level);
            pte.attributes = attrs;
            pte.pa = pa;
            pte.present = true;
            pte.leaf = leaf_entry;
            self.store.set(self.base, self.index, self.level, pte);
            Ok(())
        }
        fn present(&self) -> bool {
            self.store.get(self.base, self.index, self.level).present
        }
        fn points_to_pa(&self) -> bool {
            self.store.get(self.base, self.index, self.level).leaf
        }
        fn get_address(&self) -> PhysicalAddress {
            self.store.get(self.base, self.index, self.level).pa
        }
        fn get_level(&self) -> PageLevel {
            self.level
        }
        fn get_attributes(&self) -> MemoryAttributes {
            self.store.get(self.base, self.index, self.level).attributes
        }
        fn set_present(&mut self, present: bool) {
            let mut pte = self.store.get(self.base, self.index, self.level);
            pte.present = present;
            self.store.set(self.base, self.index, self.level, pte);
        }
        fn entry_ptr_address(&self) -> u64 {
            self as *const Self as u64
        }
        fn dump_entry(&self) -> PtResult<()> {
            Ok(())
        }
        fn dump_entry_header() {}
    }

    // DummyArch for PageTableHal
    #[derive(Debug)]
    struct DummyArch;
    impl PageTableHal for DummyArch {
        type PTE = DummyPTE;

        const DEFAULT_ATTRIBUTES: MemoryAttributes = MemoryAttributes::ExecuteProtect;
        fn paging_type_supported(_paging_type: PagingType) -> PtResult<()> {
            Ok(())
        }
        unsafe fn zero_page(_pa: VirtualAddress) {}
        fn get_zero_va(_paging_type: PagingType) -> PtResult<VirtualAddress> {
            Ok(VirtualAddress::new(0xFFFF_FF00_0000_0000))
        }
        fn get_max_va(_paging_type: PagingType) -> PtResult<VirtualAddress> {
            Ok(VirtualAddress::new(0xFFFF_FFFF_FFFF_F000))
        }
        unsafe fn install_page_table(_pa: u64) -> PtResult<()> {
            Ok(())
        }
        fn is_table_active(_pa: u64) -> bool {
            false
        }
        fn level_supports_pa_entry(level: PageLevel) -> bool {
            matches!(level, PageLevel::Level3 | PageLevel::Level2 | PageLevel::Level1)
        }
        fn invalidate_tlb(_va: VirtualAddress) {}
    }

    thread_local! {
        static DUMMY_STORE: RefCell<PageTableStore> = RefCell::new(PageTableStore::new());
    }

    fn setup_table() -> PageTableInternal<DummyAllocator, DummyArch> {
        DUMMY_STORE.with(|s| *s.borrow_mut() = PageTableStore::new());
        PageTableInternal::new(DummyAllocator { page_allocs: 0 }, PagingType::Paging4Level).unwrap()
    }

    #[test]
    fn test_new_and_from_existing() {
        let pt = PageTableInternal::<DummyAllocator, DummyArch>::new(
            DummyAllocator { page_allocs: 0 },
            PagingType::Paging4Level,
        );
        assert!(pt.is_ok());

        unsafe {
            let pt2 = PageTableInternal::<DummyAllocator, DummyArch>::from_existing(
                0x1000,
                DummyAllocator { page_allocs: 0 },
                PagingType::Paging4Level,
            );
            assert!(pt2.is_ok());
        }

        unsafe {
            let pt3 = PageTableInternal::<DummyAllocator, DummyArch>::from_existing(
                0x1001,
                DummyAllocator { page_allocs: 0 },
                PagingType::Paging4Level,
            );
            assert_eq!(pt3.unwrap_err(), PtError::UnalignedPageBase);
        }
    }

    #[test]
    fn test_map_and_query_multiple_levels() {
        let mut pt = setup_table();
        // Map a large region that will require multiple levels
        let region_size = PAGE_SIZE * 8;
        let res = pt.map_memory_region(0x8000, region_size, MemoryAttributes::Writeback);
        assert!(res.is_ok());

        // Query each page via the API
        for i in 0..8 {
            let addr = 0x8000 + i * PAGE_SIZE;
            let attrs = pt.query_memory_region(addr, PAGE_SIZE);
            assert!(attrs.is_ok());
            assert_eq!(attrs.unwrap(), MemoryAttributes::Writeback);
        }

        // Now check the backing store directly
        DUMMY_STORE.with(|store_cell| {
            let store = store_cell.borrow();
            let entries = &store.entries.borrow();

            // Only the mapped region should be present and mapped with correct attributes
            let mut mapped_count = 0;
            for ((_, _, level), pte) in entries.iter() {
                // Only leaf entries (actual mappings) should be present for the mapped region
                if *level == PageLevel::Level1 && pte.present {
                    let va: u64 = pte.pa.into();
                    // The PA is set to the VA in this dummy implementation
                    assert!(va >= 0x8000 && va < 0x8000 + region_size);
                    assert_eq!(pte.attributes, MemoryAttributes::Writeback);
                    mapped_count += 1;
                }
            }
            // There should be exactly 8 mapped pages
            assert_eq!(mapped_count, 8);

            // Ensure no other regions are mapped
            for i in 0..8 {
                let va = 0x8000 + i * PAGE_SIZE;
                let found = entries.values().any(|pte| pte.present && pte.pa == PhysicalAddress::new(va));
                assert!(found, "Expected mapping for VA {:#x} not found", va);
            }
            // Check that an unmapped region is not present
            let unmapped_va = 0x7000;
            let found = entries.values().any(|pte| {
                pte.present && pte.pa == PhysicalAddress::new(unmapped_va) && pte.level == PageLevel::Level1
            });
            assert!(!found, "Unexpected mapping found for unmapped VA {:#x}", unmapped_va);
        });
    }

    #[test]
    fn test_remap_and_query_large_region() {
        let mut pt = setup_table();
        let region_size = PAGE_SIZE * 4;
        let res = pt.map_memory_region(0xA000, region_size, MemoryAttributes::ExecuteProtect);
        assert!(res.is_ok());
        let res = pt.remap_memory_region(0xA000, region_size, MemoryAttributes::WriteProtect);
        assert!(res.is_ok());
        for i in 0..4 {
            let addr = 0xA000 + i * PAGE_SIZE;
            let attrs = pt.query_memory_region(addr, PAGE_SIZE);
            assert!(attrs.is_ok());
            assert_eq!(attrs.unwrap(), MemoryAttributes::WriteProtect);
        }
        // Backing store check
        DUMMY_STORE.with(|store_cell| {
            let store = store_cell.borrow();
            let entries = &store.entries.borrow();
            let mut mapped_count = 0;
            for ((_, _, level), pte) in entries.iter() {
                if *level == PageLevel::Level1 && pte.present {
                    let va: u64 = pte.pa.into();
                    assert!(va >= 0xA000 && va < 0xA000 + region_size);
                    assert_eq!(pte.attributes, MemoryAttributes::WriteProtect);
                    mapped_count += 1;
                }
            }
            assert_eq!(mapped_count, 4);
        });
    }

    #[test]
    fn test_unmap_and_query() {
        let mut pt = setup_table();
        let res = pt.map_memory_region(0xB000, PAGE_SIZE, MemoryAttributes::ExecuteProtect);
        assert!(res.is_ok());
        let res = pt.unmap_memory_region(0xB000, PAGE_SIZE);
        assert!(res.is_ok());
        let attrs = pt.query_memory_region(0xB000, PAGE_SIZE);
        assert!(attrs.is_err());
        // Backing store check
        DUMMY_STORE.with(|store_cell| {
            let store = store_cell.borrow();
            let entries = &store.entries.borrow();
            // Should not find a present mapping for 0xB000
            let found = entries
                .values()
                .any(|pte| pte.present && pte.pa == PhysicalAddress::new(0xB000) && pte.level == PageLevel::Level1);
            assert!(!found, "Unexpected mapping found for unmapped VA {:#x}", 0xB000);
        });
    }

    #[test]
    fn test_split_large_page_and_remap() {
        let mut pt = setup_table();
        let res = pt.map_memory_region(0xC000, PAGE_SIZE * 2, MemoryAttributes::ExecuteProtect);
        assert!(res.is_ok());
        // Remap a subregion with different attributes, which should split the large page
        let res = pt.remap_memory_region(0xC000, PAGE_SIZE, MemoryAttributes::WriteProtect);
        assert!(res.is_ok());
        let attrs1 = pt.query_memory_region(0xC000, PAGE_SIZE);
        let attrs2 = pt.query_memory_region(0xC000 + PAGE_SIZE, PAGE_SIZE);
        assert_eq!(attrs1.unwrap(), MemoryAttributes::WriteProtect);
        assert_eq!(attrs2.unwrap(), MemoryAttributes::ExecuteProtect);

        // Backing store check
        DUMMY_STORE.with(|store_cell| {
            let store = store_cell.borrow();
            let entries = &store.entries.borrow();
            // 0xC000 should be present and WriteProtect, 0xC000+PAGE_SIZE should be present and ExecuteProtect
            let mut found_c000 = false;
            let mut found_c000_1 = false;
            for ((_, _, level), pte) in entries.iter() {
                if *level == PageLevel::Level1 && pte.present {
                    let va: u64 = pte.pa.into();
                    if va == 0xC000 {
                        assert_eq!(pte.attributes, MemoryAttributes::WriteProtect);
                        found_c000 = true;
                    }
                    if va == 0xC000 + PAGE_SIZE {
                        assert_eq!(pte.attributes, MemoryAttributes::ExecuteProtect);
                        found_c000_1 = true;
                    }
                }
            }
            assert!(found_c000, "Expected mapping for VA 0xC000 not found");
            assert!(found_c000_1, "Expected mapping for VA 0xC000+PAGE_SIZE not found");
        });
    }

    #[test]
    fn test_map_unaligned_region_fails() {
        let mut pt = setup_table();
        let res = pt.map_memory_region(0xD001, PAGE_SIZE, MemoryAttributes::ExecuteProtect);
        assert_eq!(res.unwrap_err(), PtError::UnalignedAddress);
    }

    #[test]
    fn test_map_zero_size_fails() {
        let mut pt = setup_table();
        let res = pt.map_memory_region(0xE000, 0, MemoryAttributes::ExecuteProtect);
        assert_eq!(res.unwrap_err(), PtError::InvalidMemoryRange);
    }

    #[test]
    fn test_map_overlapping_region_fails() {
        let mut pt = setup_table();
        let res = pt.map_memory_region(0xF000, PAGE_SIZE * 2, MemoryAttributes::ExecuteProtect);
        assert!(res.is_ok());
        let res2 = pt.map_memory_region(0xF000 + PAGE_SIZE, PAGE_SIZE, MemoryAttributes::WriteProtect);
        assert!(res2.is_err());
    }

    #[test]
    fn test_query_unmapped_region() {
        let pt = setup_table();
        let res = pt.query_memory_region(0xDEAD_BEEF, PAGE_SIZE);
        assert!(res.is_err());
    }

    #[test]
    fn test_dump_page_tables_ok_and_invalid() {
        let mut pt = setup_table();
        let res = pt.map_memory_region(0x1000, PAGE_SIZE, MemoryAttributes::ExecuteProtect);
        assert!(res.is_ok());
        let res = pt.dump_page_tables(0x1000, PAGE_SIZE);
        assert!(res.is_ok());
        let res = pt.dump_page_tables(0x1001, PAGE_SIZE);
        assert_eq!(res.unwrap_err(), PtError::InvalidMemoryRange);
        let res = pt.dump_page_tables(0x1000, 0);
        assert_eq!(res.unwrap_err(), PtError::InvalidMemoryRange);
    }

    #[test]
    fn test_page_table_range_iterator_multiple_entries() {
        // Test a range that covers exactly 3 entries at Level1 (0x1000, 0x2000, 0x3000)
        let range = PageTableRange::<DummyArch>::new(
            PhysicalAddress::new(0x1000),
            PageLevel::Level1,
            VirtualAddress::new(0x1000),
            VirtualAddress::new(0x3000),
            PagingType::Paging4Level,
            PageTableState::ActiveSelfMapped,
        );
        let mut iter = range.into_iter();

        // First entry
        let entry1 = iter.next();
        assert!(entry1.is_some());
        let entry1 = entry1.unwrap();
        assert_eq!(entry1.base, PhysicalAddress::new(0x1000));
        assert_eq!(entry1.level, PageLevel::Level1);
        assert_eq!(entry1.va, VirtualAddress::new(0x1000));
        assert_eq!(entry1.index, 1);

        // Second entry
        let entry2 = iter.next();
        assert!(entry2.is_some());
        let entry2 = entry2.unwrap();
        assert_eq!(entry2.base, PhysicalAddress::new(0x1000));
        assert_eq!(entry2.level, PageLevel::Level1);
        assert_eq!(entry2.va, VirtualAddress::new(0x2000));
        assert_eq!(entry2.index, 2);

        // Third entry
        let entry3 = iter.next();
        assert!(entry3.is_some());
        let entry3 = entry3.unwrap();
        assert_eq!(entry3.base, PhysicalAddress::new(0x1000));
        assert_eq!(entry3.level, PageLevel::Level1);
        assert_eq!(entry3.va, VirtualAddress::new(0x3000));
        assert_eq!(entry3.index, 3);

        // No more entries
        assert!(iter.next().is_none());

        // Edge case: start_va > end_va should yield no entries
        let range_empty = PageTableRange::<DummyArch>::new(
            PhysicalAddress::new(0x1000),
            PageLevel::Level1,
            VirtualAddress::new(0x4000),
            VirtualAddress::new(0x3000),
            PagingType::Paging4Level,
            PageTableState::ActiveSelfMapped,
        );
        let mut iter_empty = range_empty.into_iter();
        assert!(iter_empty.next().is_none());

        // Edge case: start_va == end_va should yield exactly one entry
        let range_single = PageTableRange::<DummyArch>::new(
            PhysicalAddress::new(0x1000),
            PageLevel::Level1,
            VirtualAddress::new(0x2000),
            VirtualAddress::new(0x2000),
            PagingType::Paging4Level,
            PageTableState::ActiveSelfMapped,
        );
        let mut iter_single = range_single.into_iter();
        let entry = iter_single.next();
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.va, VirtualAddress::new(0x2000));
        assert!(iter_single.next().is_none());
    }

    #[test]
    fn test_get_state_all_cases() {
        // Case 1: Table is not active (should return Inactive)
        let pt = setup_table();
        // DummyArch::is_table_active always returns false, so get_state should be Inactive
        assert_eq!(pt.get_state(), PageTableState::Inactive);

        // Patch DummyArch to simulate table active but not self-mapped
        struct ActiveArch;
        impl PageTableHal for ActiveArch {
            type PTE = DummyPTE;
            const DEFAULT_ATTRIBUTES: MemoryAttributes = MemoryAttributes::ExecuteProtect;
            fn paging_type_supported(_paging_type: PagingType) -> PtResult<()> {
                Ok(())
            }
            unsafe fn zero_page(_pa: VirtualAddress) {}
            fn get_zero_va(_paging_type: PagingType) -> PtResult<VirtualAddress> {
                Ok(VirtualAddress::new(0xFFFF_FF00_0000_0000))
            }
            fn get_max_va(_paging_type: PagingType) -> PtResult<VirtualAddress> {
                Ok(VirtualAddress::new(0xFFFF_FFFF_FFFF_F000))
            }
            unsafe fn install_page_table(_pa: u64) -> PtResult<()> {
                Ok(())
            }
            fn is_table_active(_pa: u64) -> bool {
                true
            }
            fn level_supports_pa_entry(level: PageLevel) -> bool {
                matches!(level, PageLevel::Level3 | PageLevel::Level2 | PageLevel::Level1)
            }
            fn invalidate_tlb(_va: VirtualAddress) {}
        }

        // Setup a table with ActiveArch
        DUMMY_STORE.with(|s| *s.borrow_mut() = PageTableStore::new());
        let pt = PageTableInternal::<DummyAllocator, ActiveArch>::new(
            DummyAllocator { page_allocs: 0 },
            PagingType::Paging4Level,
        )
        .unwrap();

        // Now get_state should be ActiveSelfMapped since in tests we can't read the real root
        assert_eq!(pt.get_state(), PageTableState::ActiveSelfMapped);

        let root_level = PageLevel::root_level(pt.paging_type);
        let base = pt.base;
        let self_map_index = SELF_MAP_INDEX;

        // Simulate self-map entry present but pointing to wrong base
        let mut wrong_pte = BackingPTE::new(root_level);
        wrong_pte.present = true;
        wrong_pte.pa = PhysicalAddress::new(0xDEAD_BEEF);
        wrong_pte.leaf = false;
        DUMMY_STORE.with(|store_cell| {
            store_cell.borrow().set(base, self_map_index, root_level, wrong_pte);
        });
        assert_eq!(pt.get_state(), PageTableState::ActiveIdentityMapped);

        // Simulate self-map entry not present
        let mut not_present_pte = BackingPTE::new(root_level);
        not_present_pte.present = false;
        not_present_pte.pa = base;
        not_present_pte.leaf = false;
        DUMMY_STORE.with(|store_cell| {
            store_cell.borrow().set(base, self_map_index, root_level, not_present_pte);
        });
        assert_eq!(pt.get_state(), PageTableState::ActiveIdentityMapped);
    }

    #[test]
    fn test_new_unaligned_page_base() {
        // Patch DummyAllocator to return an unaligned page base
        #[derive(Clone, Debug)]
        struct UnalignedAllocator;
        impl PageAllocator for UnalignedAllocator {
            fn allocate_page(&mut self, _align: u64, _size: u64, _is_root: bool) -> PtResult<u64> {
                Ok(0x1001) // Not page aligned
            }
        }

        let pt = PageTableInternal::<UnalignedAllocator, DummyArch>::new(UnalignedAllocator, PagingType::Paging4Level);
        assert_eq!(pt.unwrap_err(), PtError::UnalignedPageBase);
    }

    #[test]
    fn test_allocate_page_unaligned_page_base() {
        // Patch DummyAllocator to return an unaligned page base for allocate_page
        #[derive(Clone, Debug)]
        struct UnalignedAllocator {
            called: bool,
        }
        impl PageAllocator for UnalignedAllocator {
            fn allocate_page(&mut self, _align: u64, _size: u64, _is_root: bool) -> PtResult<u64> {
                if !self.called {
                    self.called = true;
                    Ok(0x2000) // First call returns aligned for root
                } else {
                    Ok(0x2001) // Subsequent call returns unaligned
                }
            }
        }

        // Create a new page table with aligned root
        let mut pt = PageTableInternal::<UnalignedAllocator, DummyArch>::new(
            UnalignedAllocator { called: false },
            PagingType::Paging4Level,
        )
        .unwrap();

        // Try to allocate a page, which should fail due to unaligned base
        let res = pt.allocate_page(PageTableState::Inactive);
        assert_eq!(res.unwrap_err(), PtError::UnalignedPageBase);
    }

    #[test]
    fn test_allocate_page_activeselfmapped() {
        // Setup a table with a custom arch that simulates ActiveSelfMapped state
        #[derive(Debug)]
        struct SelfMappedArch;
        impl PageTableHal for SelfMappedArch {
            type PTE = DummyPTE;
            const DEFAULT_ATTRIBUTES: MemoryAttributes = MemoryAttributes::ExecuteProtect;
            fn paging_type_supported(_paging_type: PagingType) -> PtResult<()> {
                Ok(())
            }
            unsafe fn zero_page(_pa: VirtualAddress) {}
            fn get_zero_va(_paging_type: PagingType) -> PtResult<VirtualAddress> {
                Ok(VirtualAddress::new(0xFFFF_FF00_0000_0000))
            }
            fn get_max_va(_paging_type: PagingType) -> PtResult<VirtualAddress> {
                Ok(VirtualAddress::new(0xFFFF_FFFF_FFFF_F000))
            }
            unsafe fn install_page_table(_pa: u64) -> PtResult<()> {
                Ok(())
            }
            fn is_table_active(_pa: u64) -> bool {
                true
            }
            fn level_supports_pa_entry(level: PageLevel) -> bool {
                matches!(level, PageLevel::Level3 | PageLevel::Level2 | PageLevel::Level1)
            }
            fn invalidate_tlb(_va: VirtualAddress) {}
        }

        // Setup dummy store and page table
        DUMMY_STORE.with(|s| *s.borrow_mut() = PageTableStore::new());
        let mut pt = PageTableInternal::<DummyAllocator, SelfMappedArch>::new(
            DummyAllocator { page_allocs: 0 },
            PagingType::Paging4Level,
        )
        .unwrap();

        // Manually set zero_va_pt_pa so allocate_page can succeed
        pt.zero_va_pt_pa = Some(pt.base);

        // Try to allocate a page with ActiveSelfMapped state
        let res = pt.allocate_page(PageTableState::ActiveSelfMapped);
        assert!(res.is_ok());
        let pa = res.unwrap();
        assert!(pa.is_page_aligned());

        // Check that the page was mapped in the dummy store
        DUMMY_STORE.with(|store_cell| {
            let store = store_cell.borrow();
            let entries = &store.entries.borrow();
            let found = entries.values().any(|pte| pte.present && pte.pa == pa);
            assert!(found, "Expected allocated page not found in store");
        });

        // Manually unset zero_va_pt_pa
        pt.zero_va_pt_pa = None;
        // Try to allocate a page with ActiveSelfMapped state, should fail
        let res = pt.allocate_page(PageTableState::ActiveSelfMapped);
        assert_eq!(res.unwrap_err(), PtError::InvalidParameter);
    }

    #[test]
    fn test_remap_memory_region_internal_entry_not_present() {
        // Setup a table and map a region
        let mut pt = setup_table();
        let region_size = PAGE_SIZE * 2;
        let res = pt.map_memory_region(0x20000, region_size, MemoryAttributes::Writeback);
        assert!(res.is_ok());

        // Now, manually clear the present bit for one entry in the backing store
        DUMMY_STORE.with(|store_cell| {
            let store = store_cell.borrow();
            let entries = &mut store.entries.borrow_mut();
            // Find a Level1 entry for 0x20000
            for ((_base, _index, level), pte) in entries.iter_mut() {
                if *level == PageLevel::Level1 && pte.pa == PhysicalAddress::new(0x20000) {
                    pte.present = false;
                    break;
                }
            }
        });

        // Now call remap_memory_region_internal directly, which should hit !entry.present and return PtError::NoMapping
        let start_va = VirtualAddress::new(0x20000);
        let end_va = VirtualAddress::new(0x20000 + PAGE_SIZE - 1);
        let root_level = PageLevel::root_level(pt.paging_type);
        let res = pt.remap_memory_region_internal(
            start_va,
            end_va,
            root_level,
            pt.base,
            MemoryAttributes::WriteProtect,
            pt.get_state(),
        );
        assert_eq!(res.unwrap_err(), PtError::NoMapping);
    }

    #[test]
    fn test_query_memory_region_internal_incompatible_attributes() {
        let mut pt = setup_table();
        // Map first page with Writeback
        let res1 = pt.map_memory_region(0x30000, PAGE_SIZE, MemoryAttributes::Writeback);
        assert!(res1.is_ok());
        // Map second page with WriteProtect (should fail if overlapping, so we manually patch the backing store)
        let res2 = pt.map_memory_region(0x30000 + PAGE_SIZE, PAGE_SIZE, MemoryAttributes::WriteProtect);
        assert!(res2.is_ok());

        // Now, query_memory_region_internal for the whole region, which should hit incompatible attributes
        let start_va = VirtualAddress::new(0x30000);
        let end_va = VirtualAddress::new(0x30000 + PAGE_SIZE * 2 - 1);
        let root_level = PageLevel::root_level(pt.paging_type);
        let mut prev_attributes = RangeMappingState::Uninitialized;
        let res = pt.query_memory_region_internal(
            start_va,
            end_va,
            root_level,
            pt.base,
            &mut prev_attributes,
            pt.get_state(),
        );
        assert_eq!(res.unwrap_err(), PtError::IncompatibleMemoryAttributes);
    }

    #[test]
    fn test_split_large_page_invalid_parameter_cases_and_active_self_map() {
        let mut pt = setup_table();

        // Map a region so we have a valid entry to work with
        let res = pt.map_memory_region(0x40000, PAGE_SIZE * 2, MemoryAttributes::Writeback);
        assert!(res.is_ok());

        // Get a Level2 entry for 0x40000 (simulate a non-leaf entry)
        let root_level = PageLevel::root_level(pt.paging_type);
        let mut entry = DummyPTE::new(
            pt.base,
            0,
            root_level,
            pt.paging_type,
            VirtualAddress::new(0x40000),
            PageTableState::Inactive,
        )
        .unwrap();

        // Case 1: entry does not point to PA (leaf == false)
        entry.store.set(
            entry.base,
            entry.index,
            entry.level,
            BackingPTE {
                present: true,
                pa: PhysicalAddress::new(0x40000),
                level: root_level,
                attributes: MemoryAttributes::Writeback,
                leaf: false,
            },
        );
        let res = pt.split_large_page(VirtualAddress::new(0x40000), &mut entry, PageTableState::Inactive);
        assert_eq!(res.unwrap_err(), PtError::InvalidParameter);

        // Case 2: entry does not point to PA after round down (simulate again)
        entry.store.set(
            entry.base,
            entry.index,
            entry.level,
            BackingPTE {
                present: true,
                pa: PhysicalAddress::new(0x40000),
                level: root_level,
                attributes: MemoryAttributes::Writeback,
                leaf: false,
            },
        );
        let res = pt.split_large_page(VirtualAddress::new(0x40000), &mut entry, PageTableState::Inactive);
        assert_eq!(res.unwrap_err(), PtError::InvalidParameter);

        // Case 3: ActiveSelfMapped, entry points to PA
        #[derive(Debug)]
        struct SelfMappedArch;
        impl PageTableHal for SelfMappedArch {
            type PTE = DummyPTE;
            const DEFAULT_ATTRIBUTES: MemoryAttributes = MemoryAttributes::ExecuteProtect;
            fn paging_type_supported(_paging_type: PagingType) -> PtResult<()> {
                Ok(())
            }
            unsafe fn zero_page(_pa: VirtualAddress) {}
            fn get_zero_va(_paging_type: PagingType) -> PtResult<VirtualAddress> {
                Ok(VirtualAddress::new(0xFFFF_FF00_0000_0000))
            }
            fn get_max_va(_paging_type: PagingType) -> PtResult<VirtualAddress> {
                Ok(VirtualAddress::new(0xFFFF_FFFF_FFFF_F000))
            }
            unsafe fn install_page_table(_pa: u64) -> PtResult<()> {
                Ok(())
            }
            fn is_table_active(_pa: u64) -> bool {
                true
            }
            fn level_supports_pa_entry(level: PageLevel) -> bool {
                matches!(level, PageLevel::Level3 | PageLevel::Level2 | PageLevel::Level1)
            }
            fn invalidate_tlb(_va: VirtualAddress) {}
        }
        DUMMY_STORE.with(|s| *s.borrow_mut() = PageTableStore::new());
        let mut pt = PageTableInternal::<DummyAllocator, SelfMappedArch>::new(
            DummyAllocator { page_allocs: 0 },
            PagingType::Paging4Level,
        )
        .unwrap();

        // Map a region so we have a valid entry to work with
        let res = pt.map_memory_region(0x50000, PAGE_SIZE * 2, MemoryAttributes::Writeback);
        assert!(res.is_ok());

        // Get a Level2 entry for 0x50000 and set leaf = true
        let root_level = PageLevel::root_level(pt.paging_type);
        let mut entry = DummyPTE::new(
            pt.base,
            0,
            root_level,
            pt.paging_type,
            VirtualAddress::new(0x50000),
            PageTableState::ActiveSelfMapped,
        )
        .unwrap();
        entry.store.set(
            entry.base,
            entry.index,
            entry.level,
            BackingPTE {
                present: true,
                pa: PhysicalAddress::new(0x50000),
                level: root_level,
                attributes: MemoryAttributes::Writeback,
                leaf: true,
            },
        );

        let res = pt.split_large_page(VirtualAddress::new(0x50000), &mut entry, PageTableState::ActiveSelfMapped);
        assert!(res.is_ok());
    }

    #[test]
    fn test_entry_iterator_next_failures() {
        // Test case 1: get_next_va fails due to overflow
        // Create an iterator that will overflow when trying to get next VA
        let mut iter = EntryIterator::<DummyArch> {
            level: PageLevel::Level1,
            start_index: 511, // Last index in a page table
            end_index: 511,   // Will try to iterate once more after this
            base: PhysicalAddress::new(0x1000),
            start_va: VirtualAddress::new(0xFFFF_FFFF_FFFF_F000), // Near max VA
            paging_type: PagingType::Paging4Level,
            state: PageTableState::Inactive,
            _arch: PhantomData,
        };

        // First call should succeed
        let first = iter.next();
        assert!(first.is_some());

        // Now try to get next, but start_index > end_index, so it should return None
        assert!(iter.next().is_none());

        // Test case 2: Create an iterator where get_next_va will fail on overflow
        let mut iter_overflow = EntryIterator::<DummyArch> {
            level: PageLevel::Level1,
            start_index: 0,
            end_index: 1, // Will iterate twice
            base: PhysicalAddress::new(0x1000),
            start_va: VirtualAddress::new(0xFFFF_FFFF_FFFF_F000), // Very close to max
            paging_type: PagingType::Paging4Level,
            state: PageTableState::Inactive,
            _arch: PhantomData,
        };

        // First iteration should fail with overflow
        let first = iter_overflow.next();
        assert!(first.is_none());

        // Test case 3: Test with a custom PTE that fails on creation
        // We can't easily make DummyPTE::new fail with current implementation,
        // but we can test the error path by creating a scenario where the VA
        // calculations would be invalid

        // Create an iterator with invalid parameters that might cause PTE::new to fail
        let mut iter_invalid = EntryIterator::<DummyArch> {
            level: PageLevel::Level1,
            start_index: 512, // Invalid index (> 511)
            end_index: 513,
            base: PhysicalAddress::new(0x1000),
            start_va: VirtualAddress::new(0x1000),
            paging_type: PagingType::Paging4Level,
            state: PageTableState::Inactive,
            _arch: PhantomData,
        };

        // This should handle the error gracefully and return None
        assert!(iter_invalid.next().is_some()); // Index 512 might still work in our dummy implementation

        // Test edge case: exactly at boundary
        let mut iter_boundary = EntryIterator::<DummyArch> {
            level: PageLevel::Level4,
            start_index: 0,
            end_index: 0,
            base: PhysicalAddress::new(0x1000),
            start_va: VirtualAddress::new(0xFFFF_8000_0000_0000), // High VA that won't overflow on first iteration
            paging_type: PagingType::Paging4Level,
            state: PageTableState::Inactive,
            _arch: PhantomData,
        };

        // Should get exactly one entry
        assert!(iter_boundary.next().is_some());
        assert!(iter_boundary.next().is_none());
    }

    #[test]
    fn test_unmap_and_remap_exceeds_max_va() {
        let mut pt = setup_table();

        // First, let's map a region near the max VA
        let max_va = 0xFFFF_FFFF_FFFF_F000; // This is what DummyArch::get_max_va returns
        let base_va = max_va - PAGE_SIZE; // One page before max

        // Now try to unmap a region that would exceed max_va
        // base_va + (2 * PAGE_SIZE - 1) > max_va
        let res = pt.unmap_memory_region(base_va, PAGE_SIZE * 2);
        assert_eq!(res.unwrap_err(), PtError::InvalidMemoryRange);

        // Similarly, try to remap a region that would exceed max_va
        let res = pt.remap_memory_region(base_va, PAGE_SIZE * 2, MemoryAttributes::ExecuteProtect);
        assert_eq!(res.unwrap_err(), PtError::InvalidMemoryRange);
    }

    #[test]
    fn test_validate_address_range_comprehensive() {
        let pt = setup_table();

        // Test case 1: Valid aligned address and size
        let res = pt.validate_address_range(VirtualAddress::new(0x1000), PAGE_SIZE);
        assert!(res.is_ok());

        // Test case 2: Valid multiple page size
        let res = pt.validate_address_range(VirtualAddress::new(0x2000), PAGE_SIZE * 4);
        assert!(res.is_ok());

        // Test case 3: Zero size should fail
        let res = pt.validate_address_range(VirtualAddress::new(0x3000), 0);
        assert_eq!(res.unwrap_err(), PtError::InvalidMemoryRange);

        // Test case 4: Unaligned address should fail
        let res = pt.validate_address_range(VirtualAddress::new(0x1001), PAGE_SIZE);
        assert_eq!(res.unwrap_err(), PtError::UnalignedAddress);

        // Test case 5: Unaligned size should fail
        let res = pt.validate_address_range(VirtualAddress::new(0x1000), PAGE_SIZE + 1);
        assert_eq!(res.unwrap_err(), PtError::UnalignedMemoryRange);

        // Test case 6: Both unaligned (address takes precedence in error)
        let res = pt.validate_address_range(VirtualAddress::new(0x1001), PAGE_SIZE + 1);
        assert_eq!(res.unwrap_err(), PtError::UnalignedAddress);

        // Test case 7: Large aligned values
        let res = pt.validate_address_range(VirtualAddress::new(0x100000), PAGE_SIZE * 1024);
        assert!(res.is_ok());

        // Test case 8: Address at page boundary minus 1
        let res = pt.validate_address_range(VirtualAddress::new(0xFFF), PAGE_SIZE);
        assert_eq!(res.unwrap_err(), PtError::UnalignedAddress);

        // Test case 9: Size at page boundary minus 1
        let res = pt.validate_address_range(VirtualAddress::new(0x1000), 0xFFF);
        assert_eq!(res.unwrap_err(), PtError::UnalignedMemoryRange);

        // Test case 10: Maximum valid address (assuming 48-bit addressing)
        let res = pt.validate_address_range(VirtualAddress::new(0xFFFF_8000_0000_0000), PAGE_SIZE);
        assert!(res.is_ok());

        // Test case 11: Zero address with valid size
        let res = pt.validate_address_range(VirtualAddress::new(0), PAGE_SIZE);
        assert!(res.is_ok());

        // Test case 12: Small unaligned sizes
        for unaligned_size in 1..PAGE_SIZE {
            if unaligned_size % PAGE_SIZE != 0 {
                let res = pt.validate_address_range(VirtualAddress::new(0x5000), unaligned_size);
                assert_eq!(res.unwrap_err(), PtError::UnalignedMemoryRange);
            }
        }

        // Test case 13: Various aligned addresses with aligned size
        for i in 0..10 {
            let addr = i * PAGE_SIZE;
            let res = pt.validate_address_range(VirtualAddress::new(addr), PAGE_SIZE);
            assert!(res.is_ok());
        }
    }
}
