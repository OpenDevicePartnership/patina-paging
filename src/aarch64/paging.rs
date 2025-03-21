use super::{
    pagetablestore::{AArch64PageTableEntry, AArch64PageTableStore},
    reg,
    structs::*,
};
use crate::{
    page_allocator::PageAllocator, MemoryAttributes, PageTable, PagingType, PtError, PtResult, RangeMappingState,
    SIZE_16TB, SIZE_1TB, SIZE_256TB, SIZE_4GB, SIZE_4TB, SIZE_64GB,
};

const MAX_VA_BITS: u64 = 48;

/// Default attributes for intermediate tables. These are ignored in normal
/// operation, but should be valid for self-map usage.
const TABLE_ATTRIBUTES: MemoryAttributes = MemoryAttributes::Writeback;

#[cfg(all(not(test), target_arch = "aarch64"))]
extern "C" {
    static replace_live_xlat_entry_size: u32;
}

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
    zero_va_pt_pa: Option<PhysicalAddress>,
}

impl<A: PageAllocator> AArch64PageTable<A> {
    pub fn new(mut page_allocator: A, paging_type: PagingType) -> PtResult<Self> {
        // Allocate the root page table
        #[cfg(all(not(test), target_arch = "aarch64"))]
        if !reg::is_mmu_enabled() {
            // This is guarded behind the mmu check because enabling mmu will also
            // enable data and instruction cache. So, we don't need to manually do
            // this if mmu is already enabled.
            let function_pointer = reg::replace_live_xlat_entry as *const () as u64;
            reg::cache_range_operation(
                function_pointer,
                unsafe { replace_live_xlat_entry_size } as u64,
                reg::CpuFlushType::EfiCpuFlushTypeWriteBack,
            );
        }

        let base = page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, true)?;
        assert!(PhysicalAddress::new(base).is_4kb_aligned());
        if !reg::is_mmu_enabled() {
            reg::cache_range_operation(base, PAGE_SIZE, reg::CpuFlushType::EFiCpuFlushTypeInvalidate);
        }

        // SAFETY: We just allocated the page, so it is safe to use it.
        // We always need to zero any pages, as our contract with the page_allocator does not specify that we will
        // get zeroed pages. Random data in the page could confuse this code and make us believe there are existing
        // entries in the page table.
        unsafe { reg::zero_page(base) };

        // allocate the pages to map the zero VA range
        let pa_array = [
            page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, false)?,
            page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, false)?,
            page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, false)?,
        ];

        pa_array.iter().for_each(|pa| {
            if !reg::is_mmu_enabled() {
                reg::cache_range_operation(*pa, PAGE_SIZE, reg::CpuFlushType::EFiCpuFlushTypeInvalidate);
            }

            unsafe { reg::zero_page(*pa) };
        });

        let pa_array: [PhysicalAddress; 3] = pa_array.map(Into::into);

        // SAFETY: We just allocated the page, so it is safe to use it.
        match unsafe { Self::from_existing(base, page_allocator, paging_type) } {
            Ok(mut pt) => {
                // create our self-map entry as the final entry
                let mut self_map_entry = AArch64PageTableEntry::new(
                    pt.base,
                    SELF_MAP_INDEX,
                    PageLevel::Lvl0,
                    pt.paging_type,
                    VirtualAddress::new(pt.base.into()),
                    false,
                );

                // create it with permissive attributes
                self_map_entry.update_fields(TABLE_ATTRIBUTES, pt.base, false)?;

                // now set up the zero VA range so that we can zero pages before installing them in the page table
                // this will be at index 0x1FE for the top level page table.
                // the base doesn't actually matter here since we are using the self map and will calculate the correct
                // base for the zero VA range
                let zero_va = ZERO_VA_4_LEVEL;

                let pml4_index = ZERO_VA_INDEX;
                let pml4_base = pt.base;

                // assign PA to the penultimate PML4 entry
                let mut second_last_pml4_entry = AArch64PageTableEntry::new(
                    pml4_base,
                    pml4_index,
                    PageLevel::Lvl0,
                    pt.paging_type,
                    VirtualAddress::new(zero_va),
                    false,
                );
                second_last_pml4_entry.update_fields(TABLE_ATTRIBUTES, pa_array[0], false)?;

                // set up the PDP entry
                let mut pdp_entry = AArch64PageTableEntry::new(
                    pa_array[0],
                    0,
                    PageLevel::Lvl1,
                    pt.paging_type,
                    VirtualAddress::new(zero_va),
                    false,
                );
                pdp_entry.update_fields(TABLE_ATTRIBUTES, pa_array[1], false)?;

                // set up the PD entry
                let mut pd_entry = AArch64PageTableEntry::new(
                    pa_array[1],
                    0,
                    PageLevel::Lvl2,
                    pt.paging_type,
                    VirtualAddress::new(zero_va),
                    false,
                );
                pd_entry.update_fields(TABLE_ATTRIBUTES, pa_array[2], false)?;

                // set up the PT entry
                let mut pt_entry = AArch64PageTableEntry::new(
                    pa_array[2],
                    0,
                    PageLevel::Lvl3,
                    pt.paging_type,
                    VirtualAddress::new(zero_va),
                    false,
                );
                pt_entry.update_fields(MemoryAttributes::Writeback, PhysicalAddress::new(0), true)?;
                pt_entry.set_invalid();

                pt.zero_va_pt_pa = Some(pa_array[2]);
                Ok(pt)
            }
            Err(e) => Err(e),
        }
    }

    pub fn borrow_allocator(&mut self) -> &mut A {
        &mut self.page_allocator
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

        Ok(Self { base, page_allocator, paging_type, highest_page_level, lowest_page_level, zero_va_pt_pa: None })
    }

    /// Consumes the page table structure and returns the page table root.
    pub fn into_page_table_root(self) -> u64 {
        self.base.into()
    }

    pub fn allocate_page(&mut self) -> PtResult<PhysicalAddress> {
        let base = self.page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, false)?;
        if !reg::is_mmu_enabled() {
            reg::cache_range_operation(base, PAGE_SIZE, reg::CpuFlushType::EFiCpuFlushTypeInvalidate);
        }

        // SAFETY: We just allocated the page, so it is safe to use it.
        // We always need to zero any pages, as our contract with the page_allocator does not specify that we will
        // get zeroed pages. Random data in the page could confuse this code and make us believe there are existing
        // entries in the page table.
        let zero_va = match self.is_installed_and_self_mapped() {
            true => {
                // we don't actually need this currently, but if it isn't set and we think the self map is set up,
                // something has gone very wrong
                let zero_va_pt_pa = match self.zero_va_pt_pa {
                    Some(pa) => pa,
                    _ => return Err(PtError::InvalidParameter),
                };

                let va = ZERO_VA_4_LEVEL;

                // if we have set up the zero VA, we need to map the PA we just allocated into this range to zero it
                // as we are relying on the self map to map these pages and we want to ensure break before make
                // semantics.
                // the page_base doesn't matter here because we don't use it in self-map mode, but let's still set
                // the right address in case it gets used in the future and it is easy to persist
                let mut zero_entry = AArch64PageTableEntry::new(
                    zero_va_pt_pa,
                    0,
                    PageLevel::Lvl3,
                    self.paging_type,
                    VirtualAddress::new(va),
                    true,
                );

                // in theory, this isn't needed because we the zero VA will not be our currently executing code
                // but experimentation has shown that a regular update_fields + TLB flush for VA doesn't work, but
                // invalidating the entire TLB in that case does work, so this seems less heavy.
                let _val = zero_entry.update_shadow_fields(
                    MemoryAttributes::Writeback | MemoryAttributes::ExecuteProtect,
                    base.into(),
                    true,
                );
                #[cfg(all(not(test), target_arch = "aarch64"))]
                unsafe {
                    reg::replace_live_xlat_entry(zero_entry.raw_address(), _val, va.into());
                }

                va
            }
            // If we have not installed this page table, we can't use our VA range to zero pages yet and have to go on
            // the assumption that the caller has this page mapped
            false => base,
        };

        unsafe { reg::zero_page(zero_va) };
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

        let table = AArch64PageTableStore::new(
            base,
            level,
            self.paging_type,
            start_va,
            end_va,
            self.is_installed_and_self_mapped(),
        );
        for mut entry in table {
            if !entry.is_valid()
                && level.supports_block_entry()
                && va.is_level_aligned(level)
                && va.length_through(end_va) >= level.entry_va_size()
            {
                if reg::is_this_page_table_active(self.base) {
                    // Need to do the heavy duty break-before-make sequence
                    let _val = entry.update_shadow_fields(attributes, va.into(), true);
                    #[cfg(all(not(test), target_arch = "aarch64"))]
                    unsafe {
                        reg::replace_live_xlat_entry(entry.raw_address(), _val, va.into());
                    }
                } else {
                    // Just update the entry and flush TLB
                    entry.update_fields(attributes, va.into(), true)?;
                    reg::update_translation_table_entry(entry.raw_address(), va.into());
                }
            } else {
                assert!(level != self.lowest_page_level);
                if !entry.is_valid() {
                    let pa = self.allocate_page()?;

                    if reg::is_this_page_table_active(self.base) {
                        // Need to do the heavy duty break-before-make sequence
                        let _val = entry.update_shadow_fields(TABLE_ATTRIBUTES, pa, false);
                        #[cfg(all(not(test), target_arch = "aarch64"))]
                        unsafe {
                            reg::replace_live_xlat_entry(entry.raw_address(), _val, pa.into());
                        }
                    } else {
                        // Just update the entry and flush TLB
                        entry.update_fields(TABLE_ATTRIBUTES, pa, false)?;
                        reg::update_translation_table_entry(entry.raw_address(), pa.into());
                    }
                }

                // split the va range appropriately for the next level pages
                let next_base = entry.get_canonical_page_table_base();

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

        let table = AArch64PageTableStore::new(
            base,
            level,
            self.paging_type,
            start_va,
            end_va,
            self.is_installed_and_self_mapped(),
        );
        for mut entry in table {
            if !entry.is_valid() {
                continue;
            }

            // Check if this is a large page in need of splitting.
            if entry.is_block_entry()
                && (!va.is_level_aligned(level) || va.length_through(end_va) < level.entry_va_size())
            {
                self.split_large_page(va, &mut entry)?;
            }

            if entry.is_block_entry() {
                entry.set_invalid();
            } else {
                // split the va range appropriately for the next level pages
                let next_base = entry.get_canonical_page_table_base();

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

        let table = AArch64PageTableStore::new(
            base,
            level,
            self.paging_type,
            start_va,
            end_va,
            self.is_installed_and_self_mapped(),
        );
        for mut entry in table {
            if !entry.is_valid() {
                return Err(PtError::NoMapping);
            }

            // Check if this is a large page in need of splitting.
            if entry.is_block_entry()
                && (!va.is_level_aligned(level) || va.length_through(end_va) < level.entry_va_size())
            {
                self.split_large_page(va, &mut entry)?;
            }

            if entry.is_block_entry() {
                if reg::is_this_page_table_active(self.base) {
                    // Need to do the heavy duty break-before-make sequence
                    let _val = entry.update_shadow_fields(attributes, va.into(), true);
                    #[cfg(all(not(test), target_arch = "aarch64"))]
                    unsafe {
                        reg::replace_live_xlat_entry(entry.raw_address(), _val, va.into());
                    }
                } else {
                    // Just update the entry and flush TLB
                    entry.update_fields(attributes, va.into(), true)?;
                    reg::update_translation_table_entry(entry.raw_address(), va.into());
                }
            } else {
                let next_base = entry.get_canonical_page_table_base();

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

        let table = AArch64PageTableStore::new(
            base,
            level,
            self.paging_type,
            start_va,
            end_va,
            self.is_installed_and_self_mapped(),
        );
        let mut entries = table.into_iter().peekable();
        while let Some(entry) = entries.next() {
            if !entry.is_valid() {
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

            if entry.is_block_entry() {
                // Given memory range can span multiple page table entries, in such
                // scenario, the expectation is all entries should have same attributes.
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
                    (level as u64 - 1).into(),
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
    fn split_large_page(&mut self, va: VirtualAddress, entry: &mut AArch64PageTableEntry) -> PtResult<()> {
        let level = entry.get_level();
        debug_assert!(level != self.lowest_page_level && entry.is_block_entry());

        // Round down to the nearest page boundary at the current level.
        let large_page_start: u64 = va.into();
        let large_page_start = large_page_start & !(level.entry_va_size() - 1);
        let large_page_end: u64 = large_page_start + level.entry_va_size() - 1;

        if level == self.lowest_page_level || !entry.is_block_entry() {
            return Err(PtError::InvalidParameter);
        }

        let attributes = entry.get_attributes();
        let pa = self.allocate_page()?;

        if reg::is_this_page_table_active(self.base) {
            // Need to do the heavy duty break-before-make sequence
            let _val = entry.update_shadow_fields(attributes, pa, false);
            #[cfg(all(not(test), target_arch = "aarch64"))]
            unsafe {
                reg::replace_live_xlat_entry(entry.raw_address(), _val, va.into());
            }
        } else {
            // Just update the entry and flush TLB
            entry.update_fields(attributes, pa, false)?;
            reg::update_translation_table_entry(entry.raw_address(), va.into());
        }

        // invalidate the self map VA for the region covered by the large page
        // this function gets called multiple times to split from larger pages to smaller pages, so we only invalidate
        // once for the new page table we created
        let table = AArch64PageTableStore::new(
            pa,
            level - 1,
            self.paging_type,
            large_page_start.into(),
            large_page_end.into(),
            true,
        );
        if let Some(tb_entry) = table.into_iter().next() {
            reg::update_translation_table_entry(tb_entry.raw_address(), tb_entry.raw_address());
        }

        self.map_memory_region_internal(
            large_page_start.into(),
            large_page_end.into(),
            (level as u64 - 1).into(),
            pa,
            attributes,
        )?;

        Ok(())
    }

    fn dump_page_tables_internal(
        &self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
    ) {
        let mut va = start_va;

        let table = AArch64PageTableStore::new(
            base,
            level,
            self.paging_type,
            start_va,
            end_va,
            self.is_installed_and_self_mapped(),
        );
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
            log::info!("{}|{:48}{}", level, range, entry.dump_entry());

            if !entry.is_block_entry() {
                // split the va range appropriately for the next level pages
                let next_base = entry.get_canonical_page_table_base();
                self.dump_page_tables_internal(
                    next_level_start_va,
                    next_level_end_va,
                    (level as u64 - 1).into(),
                    next_base,
                );
            }

            va = va.get_next_va(level);
        }
    }

    fn validate_address_range(&self, address: VirtualAddress, size: u64) -> PtResult<()> {
        if size == 0 {
            return Err(PtError::InvalidMemoryRange);
        }
        // Overflow check
        address.try_add(size - 1)?;

        // Check the memory range
        if address + (size - 1) > VirtualAddress::new(MAX_VA) {
            return Err(PtError::InvalidMemoryRange);
        }

        if size == 0 || !address.is_4kb_aligned() {
            return Err(PtError::UnalignedAddress);
        }

        // Check the memory range is aligned
        if !VirtualAddress::new(size).is_4kb_aligned() {
            return Err(PtError::UnalignedMemoryRange);
        }
        Ok(())
    }

    /// Check if the page table is installed and self-mapped.
    /// This is used to determine if we can use the self-map to zero pages and reference the page table pages.
    /// If our page table base is not in TTBR0 and the MMU is not enabled, self-mapped entries won't work for this page
    /// table. Similarly, if the expected self-map entry is not present or does not point to the page table base, we
    /// can't use the self-map.
    fn is_installed_and_self_mapped(&self) -> bool {
        if !reg::is_this_page_table_active(self.base) {
            return false;
        }

        // this is always read from the physical address of the page table, because we are trying to determine whether
        // we are self-mapped or not
        let self_map_entry = AArch64PageTableEntry::new(
            self.base,
            SELF_MAP_INDEX,
            self.highest_page_level,
            self.paging_type,
            self.base.into(),
            false,
        );

        if !self_map_entry.is_valid() || self_map_entry.get_canonical_page_table_base() != self.base {
            return false;
        }

        true
    }
}

impl<A: PageAllocator> PageTable for AArch64PageTable<A> {
    type ALLOCATOR = A;

    fn borrow_allocator(&mut self) -> &mut A {
        self.borrow_allocator()
    }

    fn map_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;
        if address + size - 1 > VirtualAddress::new(MAX_PA) {
            panic!(
                "Address range {:#x?} - {:#x?} exceeds maximum VA that can be supported by this crate",
                address,
                address + size - 1
            );
        }

        // We map until next alignment
        let start_va = address;
        let end_va = address + size - 1;

        self.map_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, attributes)
    }

    fn unmap_memory_region(&mut self, address: u64, size: u64) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;
        if address + size - 1 > VirtualAddress::new(MAX_PA) {
            panic!(
                "Address range {:#x?} - {:#x?} exceeds maximum VA that can be supported by this crate",
                address,
                address + size - 1
            );
        }

        let start_va = address;
        let end_va = address + size - 1;

        self.unmap_memory_region_internal(start_va, end_va, self.highest_page_level, self.base)
    }

    fn install_page_table(&mut self) -> PtResult<()> {
        // This step will need to configure the MMU and then activate it on the newly created table.

        let pa_bits = reg::get_phys_addr_bits();
        let max_address_bits = core::cmp::min(pa_bits, MAX_VA_BITS);
        let max_address = (1 << max_address_bits) - 1;

        // TCR_EL2.T0SZ defines the size of the VA space addressed by TTBR0_EL2. The VA space size is 2^(64 - t0sz) bytes.
        // We always want to set the minimum size of TCR_EL2.T0SZ to 16, which gives us a 48-bit VA space. This allows
        // us to use the self map beyond PA space (depending on platform)
        let t0sz = 16;
        let root_table_cnt = get_root_table_count(t0sz);

        let mut tcr: u64;

        if reg::get_current_el() == 2 {
            // Note: Bits 23 and 31 are reserved(RES1) bits in TCR_EL2
            tcr = t0sz | (1 << 31) | (1 << 23);

            // Set the Physical Address Size using MaxAddress
            if max_address < SIZE_4GB {
                tcr |= 0 << 16;
            } else if max_address < SIZE_64GB {
                tcr |= 1 << 16;
            } else if max_address < SIZE_1TB {
                tcr |= 2 << 16;
            } else if max_address < SIZE_4TB {
                tcr |= 3 << 16;
            } else if max_address < SIZE_16TB {
                tcr |= 4 << 16;
            } else if max_address < SIZE_256TB {
                tcr |= 5 << 16;
            } else {
                panic!("The MaxAddress 0x{:x} is not supported by this MMU configuration.", max_address);
            }
        } else if reg::get_current_el() == 1 {
            // Due to Cortex-A57 erratum #822227 we must set TG1[1] == 1, regardless of EPD1.
            tcr = t0sz | 1 << 30 | 1 << 23;

            // Set the Physical Address Size using MaxAddress
            if max_address < SIZE_4GB {
                tcr |= 0 << 32;
            } else if max_address < SIZE_64GB {
                tcr |= 1 << 32;
            } else if max_address < SIZE_1TB {
                tcr |= 2 << 32;
            } else if max_address < SIZE_4TB {
                tcr |= 3 << 32;
            } else if max_address < SIZE_16TB {
                tcr |= 4 << 32;
            } else if max_address < SIZE_256TB {
                tcr |= 5 << 32;
            } else {
                panic!("The MaxAddress 0x{:x} is not supported by this MMU configuration.", max_address);
            }
        } else {
            panic!("paging is only expected to run at EL2 and EL1, not EL3.");
        }

        //
        // Translation table walks are always cache coherent on ARMv8-A, so cache
        // maintenance on page tables is never needed. Since there is a risk of
        // loss of coherency when using mismatched attributes, and given that memory
        // is mapped cacheable except for extraordinary cases (such as non-coherent
        // DMA), have the page table walker perform cached accesses as well, and
        // assert below that matches the attributes we use for CPU accesses to
        // the region.
        //
        tcr |= 3 << 12 | 1 << 10 | 1 << 8;

        // Set TCR
        reg::set_tcr(tcr);

        if !reg::is_mmu_enabled() {
            // Make sure we are not inadvertently hitting in the caches
            // when populating the page tables.
            reg::cache_range_operation(
                self.base.into(),
                root_table_cnt * 8,
                reg::CpuFlushType::EFiCpuFlushTypeInvalidate,
            );
        }

        // EFI_MEMORY_UC ==> MAIR_ATTR_DEVICE_MEMORY
        // EFI_MEMORY_WC ==> MAIR_ATTR_NORMAL_MEMORY_NON_CACHEABLE
        // EFI_MEMORY_WT ==> MAIR_ATTR_NORMAL_MEMORY_WRITE_THROUGH
        // EFI_MEMORY_WB ==> MAIR_ATTR_NORMAL_MEMORY_WRITE_BACK
        reg::set_mair(0x44 << 8 | 0xBB << 16 | 0xFF << 24);

        // Set TTBR0
        reg::set_ttbr0(self.base.into());

        if !reg::is_mmu_enabled() {
            reg::set_alignment_check(false);
            reg::set_stack_alignment_check(true);
            reg::enable_instruction_cache();
            reg::enable_data_cache();

            reg::enable_mmu();
        }

        Ok(())
    }

    fn remap_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;
        if address + size - 1 > VirtualAddress::new(MAX_PA) {
            panic!(
                "Address range {:#x?} - {:#x?} exceeds maximum VA that can be supported by this crate",
                address,
                address + size - 1
            );
        }

        let start_va = address;
        let end_va = address + size - 1;

        // make sure the memory region has same attributes set
        let mut prev_attributes = RangeMappingState::Uninitialized;
        self.query_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, &mut prev_attributes)?;

        self.remap_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, attributes)
    }

    fn query_memory_region(&self, address: u64, size: u64) -> PtResult<MemoryAttributes> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + size - 1;

        let mut prev_attributes = RangeMappingState::Uninitialized;
        self.query_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, &mut prev_attributes)
    }

    fn dump_page_tables(&self, address: u64, size: u64) {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size).unwrap();

        let start_va = address;
        let end_va = address + size - 1;

        log::info!("start-end:[{} {}]", start_va, end_va);
        log::info!("{}", "-".repeat(130));
        self.dump_page_tables_internal(start_va, end_va, self.highest_page_level, self.base)
    }
}

fn find_num_entries(start_offset: u64, end_offset: u64, num_parent_level_entries: u64) -> u64 {
    let mut num_entries = 0;
    if num_parent_level_entries > 1 {
        // entries spanning multiple pages
        num_entries += 512 - start_offset; // number of upper entries in first page
        num_entries += (num_parent_level_entries - 2) * 512; // number of entries in between pages
        num_entries += end_offset + 1; // number of lower entries in the last page
    } else {
        // entries do not span multiple pages(end_offset is guaranteed to be higher than start offset)
        num_entries = end_offset - start_offset + 1; // number of entries in the page
    }

    num_entries
}

/// Finds the number of pages that are saved using large pages for the given address
/// range and paging levels compared for using the lowest level.
fn find_large_page_savings(address: u64, size: u64, level: PageLevel, lowest_page_level: PageLevel) -> u64 {
    // The number of large pages in a given address start & length is deterministic
    // based on the alignment of the address to the individual large pages size.
    // Recurse down through levels finding the optimal page size to use.

    if (level == lowest_page_level) || (size == 0) {
        return 0;
    }

    if !level.supports_block_entry() {
        return find_large_page_savings(address, size, level - 1, lowest_page_level);
    }

    let mut savings = 0;
    let alignment = level.entry_va_size();
    let aligned_address = (address + alignment - 1) & !(alignment - 1);

    // If there are no large pages that can be used for the given address range,
    // then continue with the next level.
    if aligned_address + alignment > address + size {
        return find_large_page_savings(address, size, level - 1, lowest_page_level);
    }

    // Split of the unaligned beginning and end and recursive to the next level
    // to find the savings with smaller page sizes.

    savings += find_large_page_savings(address, aligned_address - address, level - 1, lowest_page_level);

    let aligned_end = (address + size) & !(alignment - 1);
    let remainder = (address + size) - aligned_end;

    savings += find_large_page_savings(aligned_end, remainder, level - 1, lowest_page_level);

    // The savings is the number of sub-pages that would be saved by each large page
    // which is 1 for the current level and then 512 for each level below which.
    // e.g. a large page at the third level would save 1 + 512
    let num_large_pages = (aligned_end - aligned_address) / alignment;
    let page_entries: u64 = 512;
    let remaining_levels = level as u64 - lowest_page_level as u64;

    savings += num_large_pages;
    if remaining_levels > 1 {
        savings += num_large_pages * page_entries.pow(remaining_levels as u32 - 1);
    }

    savings
}

pub(crate) fn num_page_tables_required(address: u64, size: u64, paging_type: PagingType) -> PtResult<u64> {
    let address = VirtualAddress::new(address);
    if size == 0 || !address.is_4kb_aligned() {
        return Err(PtError::UnalignedAddress);
    }

    // Check the memory range is aligned
    if !(address + size).is_4kb_aligned() {
        return Err(PtError::UnalignedAddress);
    }

    let start_va = address;
    let end_va = address + size - 1;

    // For the given paging type identify the highest and lowest page levels.
    // This is used during page building to stop the recursion.
    let (highest_page_level, lowest_page_level) = match paging_type {
        PagingType::AArch64PageTable4KB => (PageLevel::Lvl0, PageLevel::Lvl3),
        _ => return Err(PtError::InvalidParameter),
    };

    // The key to calculate the number of tables required for the current level
    // dependents on the number of entries in the parent level. Also, the number
    // of entries in the current level depends on the number of tables in the
    // current level and the current offset(done by `find_num_entries()`).
    let mut num_entries = 0;
    let mut num_tables = 1; // top level table
    let mut total_num_tables = 0;
    for level in ((lowest_page_level as u64)..=(highest_page_level as u64)).rev() {
        let start_offset = start_va.get_index(level.into());
        let end_offset = end_va.get_index(level.into());

        num_entries = find_num_entries(start_offset, end_offset, num_entries);
        total_num_tables += num_tables;
        num_tables = num_entries;
    }

    // The above calculates only the lowest pages, now calculate saving through large
    // pages.
    let savings = find_large_page_savings(address.into(), size, highest_page_level, lowest_page_level);
    total_num_tables -= savings;

    Ok(total_num_tables)
}

fn get_root_table_count(t0sz: u64) -> u64 {
    512 >> ((t0sz - 16) % 9)
}
