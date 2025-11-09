//! Paging logic and core algorithms for managing virtual memory mappings, page table traversal, and address
//! translation.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use core::{marker::PhantomData, slice};

use crate::{
    MemoryAttributes, PagingType, PtError, RangeMappingState,
    arch::{PageTableEntry, PageTableHal},
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

#[derive(Debug)]
pub struct PageTableInternal<P: PageAllocator, Arch: PageTableHal> {
    base: PhysicalAddress,
    page_allocator: P,
    pub(crate) paging_type: PagingType,
    _arch: PhantomData<Arch>,
}

impl<P: PageAllocator, Arch: PageTableHal> PageTableInternal<P, Arch> {
    pub fn new(mut page_allocator: P, paging_type: PagingType) -> Result<Self, PtError> {
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

        let self_map_va =
            VirtualAddress::new(Arch::get_self_mapped_base(root_level, VirtualAddress::new(0), paging_type));

        // Setup the self-mapping for the top level page table.
        let self_map_entry = get_entry::<Arch>(
            root_level,
            paging_type,
            PageTableStateWithAddress::NotSelfMapped(pt.base),
            SELF_MAP_INDEX,
        )?;

        // create it with permissive attributes
        self_map_entry.update_fields(Arch::DEFAULT_ATTRIBUTES, pt.base, false, root_level, self_map_va)?;

        // Setup the zero VA entry to allow for zeroing pages before putting them in the page table.
        let mut table_base = pt.base;
        let mut level = root_level;
        let zero_va = Arch::get_zero_va(paging_type)?;
        let mut index = ZERO_VA_INDEX as usize;
        while let Some(next_level) = level.next_level() {
            let new_table = pt.page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, false)?;

            // SAFETY: We just allocated the page, so it is safe to use it.
            unsafe { Arch::zero_page(new_table.into()) };

            let entry = get_entry::<Arch>(
                level,
                paging_type,
                PageTableStateWithAddress::NotSelfMapped(table_base),
                index as u64,
            )?;
            // Arch::PTE::new(table_base, index, level, paging_type, zero_va, PageTableState::Inactive)?;
            entry.update_fields(Arch::DEFAULT_ATTRIBUTES, PhysicalAddress::new(new_table), false, level, zero_va)?;

            // After the first-level index, all other indexes are 0.
            index = 0;
            level = next_level;
            table_base = PhysicalAddress::new(new_table);
        }

        // Create the leaf zero VA entry.
        let entry =
            get_entry::<Arch>(level, paging_type, PageTableStateWithAddress::NotSelfMapped(table_base), index as u64)?;
        entry.update_fields(Arch::DEFAULT_ATTRIBUTES, PhysicalAddress::new(0), true, level, zero_va)?;
        entry.set_present_bit(false, zero_va);

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
    pub unsafe fn from_existing(base: u64, page_allocator: P, paging_type: PagingType) -> Result<Self, PtError> {
        Arch::paging_type_supported(paging_type)?;

        let base = PhysicalAddress::new(base);
        if !base.is_page_aligned() {
            return Err(PtError::UnalignedPageBase);
        }

        Ok(Self { base, page_allocator, paging_type, _arch: PhantomData })
    }

    /// Consumes the page table structure and returns the page table root.
    pub fn into_page_table_root(self) -> u64 {
        self.base.into()
    }

    pub fn allocate_page(&mut self, state: PageTableState) -> Result<PhysicalAddress, PtError> {
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

                // if we have set up the zero VA, we need to map the PA we just allocated into this range to zero it
                // as we are relying on the self map to map these pages and we want to ensure break before make
                // semantics.
                // the page_base doesn't matter here because we don't use it in self-map mode, but let's still set
                // the right address in case it gets used in the future and it is easy to persist
                let zero_entry = get_entry::<Arch>(
                    PageLevel::Level1,
                    self.paging_type,
                    PageTableStateWithAddress::SelfMapped(va),
                    0,
                )?;

                zero_entry.update_fields(
                    Arch::DEFAULT_ATTRIBUTES | MemoryAttributes::ExecuteProtect,
                    PhysicalAddress::new(base),
                    true,
                    PageLevel::Level1,
                    va,
                )?;

                Arch::invalidate_tlb(va);

                va
            }
            // If we have not installed this page table, we can't use our VA range to zero pages yet and have to go on
            // the assumption that the caller has this page mapped
            _ => base.into(),
        };

        // SAFETY: We just allocated the page and we have set up the zero VA to point to it or are relying on the
        // contract that the caller has this page mapped, so it is safe to zero it.
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
    ) -> Result<(), PtError> {
        let mut va = start_va;

        let state_with_address = match state {
            PageTableState::ActiveSelfMapped => PageTableStateWithAddress::SelfMapped(start_va),
            _ => PageTableStateWithAddress::NotSelfMapped(base),
        };
        let table = PageTableRange::<Arch>::new(level, start_va, end_va, self.paging_type, state_with_address)?;

        // there is a limitation in Rust's slice::iter_mut that will crash if we try to use a slice for the top level
        // of the self map. This can only occur in the query, due to map/unmap explicitly ensuring we are not
        // attempting those operations on the self map VA, but this pattern is replicated to all the other functions
        // for consistency. See https://github.com/rust-lang/rust/issues/146911 for more details. As such, we need to
        // work around this by simply iterating on the indices instead of the iterator
        let len = table.slice.len();
        for i in 0..len {
            let entry = &mut table.slice[i];
            // Check if this is a large page in need of splitting. We only split if the attributes of this entry
            // are changing
            if entry.get_present_bit()
                && entry.points_to_pa(level)
                && entry.get_attributes() != attributes
                && (!va.is_level_aligned(level) || va.length_through(end_va)? < level.entry_va_size())
            {
                self.split_large_page(va, entry, state, level)?;
            }

            if Arch::level_supports_pa_entry(level)
                && va.is_level_aligned(level)
                && va.length_through(end_va)? >= level.entry_va_size()
            {
                // This entry is large enough to be a whole entry for this supporting level,
                // so we can map the whole range in one go.
                entry.update_fields(attributes, va.into(), true, level, va)?;
            } else {
                let next_level = level.next_level().ok_or_else(|| {
                    log::error!("Failed to map memory region at VA {va:#x?} as the level is the lowest level and cannot be split");
                    PtError::InternalError
                })?;

                if !entry.get_present_bit() {
                    let pa = self.allocate_page(state)?;
                    // non-leaf pages should always have the most permissive memory attributes.
                    entry.update_fields(Arch::DEFAULT_ATTRIBUTES, pa, false, level, va)?;
                }
                let next_base = entry.get_next_address();

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
    ) -> Result<(), PtError> {
        let mut va = start_va;

        let state_with_address = match state {
            PageTableState::ActiveSelfMapped => PageTableStateWithAddress::SelfMapped(start_va),
            _ => PageTableStateWithAddress::NotSelfMapped(base),
        };
        let table = PageTableRange::<Arch>::new(level, start_va, end_va, self.paging_type, state_with_address)?;

        // there is a limitation in Rust's slice::iter_mut that will crash if we try to use a slice for the top level
        // of the self map. This can only occur in the query, due to map/unmap explicitly ensuring we are not
        // attempting those operations on the self map VA, but this pattern is replicated to all the other functions
        // for consistency. See https://github.com/rust-lang/rust/issues/146911 for more details. As such, we need to
        // work around this by simply iterating on the indices instead of the iterator
        let len = table.slice.len();
        for i in 0..len {
            let entry = &mut table.slice[i];
            // Check if this is a large page in need of splitting.
            if entry.points_to_pa(level)
                && entry.get_present_bit()
                && (!va.is_level_aligned(level) || va.length_through(end_va)? < level.entry_va_size())
            {
                self.split_large_page(va, entry, state, level)?;
            }

            // This is at least either the entirety of a large page or a single page.
            if entry.get_present_bit() {
                if entry.points_to_pa(level) {
                    entry.unmap(va);
                    self.invalidate_selfmap(va, state, level)?;
                } else {
                    // This should always have another level if this is not a PA entry.
                    let next_level = level.next_level().unwrap();
                    let next_base = entry.get_next_address();

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

    fn query_memory_region_internal(
        &self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
        prev_attributes: &mut RangeMappingState,
        state: PageTableState,
    ) -> Result<MemoryAttributes, PtError> {
        let mut va = start_va;

        let state_with_address = match state {
            PageTableState::ActiveSelfMapped => PageTableStateWithAddress::SelfMapped(start_va),
            _ => PageTableStateWithAddress::NotSelfMapped(base),
        };
        let table = PageTableRange::<Arch>::new(level, start_va, end_va, self.paging_type, state_with_address)?;
        // there is a limitation in Rust's slice::iter_mut that will crash if we try to use a slice for the top level
        // of the self map. This can only occur in the query, due to map/unmap explicitly ensuring we are not
        // attempting those operations on the self map VA, but this pattern is replicated to all the other functions
        // for consistency. See https://github.com/rust-lang/rust/issues/146911 for more details. As such, we need to
        // work around this by simply iterating on the indices instead of the iterator
        let len = table.slice.len();
        for i in 0..len {
            let entry = &table.slice[i];

            if !entry.get_present_bit() {
                // if we found an entry that is not present after finding entries that were already mapped,
                // we fail this with InconsistentMappingAcrossRange. If we have set found any region yet, mark
                // this as an unmapped region and continue
                match prev_attributes {
                    RangeMappingState::Uninitialized => *prev_attributes = RangeMappingState::Unmapped,
                    RangeMappingState::Mapped(_) => return Err(PtError::InconsistentMappingAcrossRange),
                    RangeMappingState::Unmapped => {}
                }

                // only calculate the next VA if there is another entry in the table we are processing
                // when processing the self map, always calculating the next VA can result in overflow needlessly
                if i + 1 < len {
                    va = va.get_next_va(level)?;
                }
                continue;
            }

            if entry.points_to_pa(level) {
                let current_attributes = entry.get_attributes();
                match prev_attributes {
                    RangeMappingState::Uninitialized => {
                        *prev_attributes = RangeMappingState::Mapped(current_attributes)
                    }
                    RangeMappingState::Unmapped => return Err(PtError::InconsistentMappingAcrossRange),
                    RangeMappingState::Mapped(attrs) => {
                        if *attrs != current_attributes {
                            return Err(PtError::NonUniformMemoryAttributes);
                        }
                    }
                }
            } else {
                let next_level = level.next_level().unwrap();
                let next_base = entry.get_next_address();

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
            if i + 1 < len {
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
    fn split_large_page(
        &mut self,
        va: VirtualAddress,
        entry: &mut Arch::PTE,
        state: PageTableState,
        level: PageLevel,
    ) -> Result<(), PtError> {
        let next_level = level.next_level().ok_or_else(|| {
            log::error!("Failed to split large page at VA {:#x?} as this is the lowest level", va);
            PtError::InvalidParameter
        })?;

        if !entry.points_to_pa(level) {
            log::error!("Failed to split large page at VA {va:#x?} as the entry does not point to a physical address",);
            return Err(PtError::InvalidParameter);
        }

        // Round down to the nearest page boundary at the current level.
        let large_page_start: u64 = va.into();
        let large_page_start = large_page_start & !(level.entry_va_size() - 1);
        let large_page_end: u64 = large_page_start + level.entry_va_size() - 1;

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
        entry.update_fields(Arch::DEFAULT_ATTRIBUTES, pa, false, level, va)?;

        // Invalidate the selfmap when needed.
        self.invalidate_selfmap(va, state, level)?;

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
    ) -> Result<(), PtError> {
        let mut va = start_va;

        // special case handling for zero VA and self map
        if va == Arch::get_zero_va(self.paging_type)? {
            log::info!("VA {va:#x?} is the zero VA");
        } else if u64::from(va) == Arch::get_self_mapped_base(PageLevel::Level1, va, self.paging_type) {
            log::info!("VA {va:#x?} is the self-mapped VA, only dumping the root entry");
            let entry = get_entry::<Arch>(
                PageLevel::root_level(self.paging_type),
                self.paging_type,
                PageTableStateWithAddress::NotSelfMapped(base),
                va.get_index(PageLevel::root_level(self.paging_type)),
            )?;
            entry.dump_entry(va, PageLevel::root_level(self.paging_type))?;
            return Ok(());
        }

        let state_with_address = match state {
            PageTableState::ActiveSelfMapped => PageTableStateWithAddress::SelfMapped(start_va),
            _ => PageTableStateWithAddress::NotSelfMapped(base),
        };
        let table = PageTableRange::<Arch>::new(level, start_va, end_va, self.paging_type, state_with_address)?;
        // there is a limitation in Rust's slice::iter_mut that will crash if we try to use a slice for the top level
        // of the self map. This can only occur in the query, due to map/unmap explicitly ensuring we are not
        // attempting those operations on the self map VA, but this pattern is replicated to all the other functions
        // for consistency. See https://github.com/rust-lang/rust/issues/146911 for more details. As such, we need to
        // work around this by simply iterating on the indices instead of the iterator
        let len = table.slice.len();
        for i in 0..len {
            let entry = &table.slice[i];

            entry.dump_entry(va, level)?;
            if !entry.get_present_bit() && !level.is_lowest_level() {
                va = va.get_next_va(level)?;
                continue;
            }

            // split the va range appropriately for the next level pages

            // start of the next level va. It will be same as current va
            let next_level_start_va = va;

            // get max va addressable by current entry
            let curr_va_ceil = va.round_up(level);

            // end of next level va. It will be minimum of next va and end va
            let next_level_end_va = VirtualAddress::min(curr_va_ceil, end_va);

            if entry.get_present_bit() && !entry.points_to_pa(level) {
                let next_base = entry.get_next_address();
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

    fn invalidate_selfmap(&self, va: VirtualAddress, state: PageTableState, level: PageLevel) -> Result<(), PtError> {
        if !matches!(state, PageTableState::ActiveSelfMapped) {
            return Ok(());
        }

        match level {
            PageLevel::Level1 => {
                // Nothing to do, self-map cannot reference level 1 physical addresses.
            }
            PageLevel::Level2 => {
                // Invalidate the self map VA for the region covered by the large page. The next level of the self map
                // may get pulled in by speculative execution, so we need to ensure the wrong mapping invalidated before
                // the entry may be used again.
                if let Ok(tb_entry) =
                    get_entry::<Arch>(PageLevel::Level1, self.paging_type, PageTableStateWithAddress::SelfMapped(va), 0)
                {
                    // Invalidate the TLB entry for the self-mapped region
                    Arch::invalidate_tlb(tb_entry.entry_ptr_address().into());
                }
            }
            _ => {
                // For pages larger then level2, there are multiple levels of self map that could have been
                // speculatively pulled in, instead of walking all these we will simply invalidate the full
                // TLB in this uncommon scenario.
                Arch::invalidate_tlb_all();
            }
        }

        Ok(())
    }

    fn validate_address_range(&self, address: VirtualAddress, size: u64) -> Result<(), PtError> {
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

        let root_level = PageLevel::root_level(self.paging_type);

        // this is always read from the physical address of the page table, because we are trying to determine whether
        // we are self-mapped or not. The root should always be accessible, only assume active for now.
        let self_map_entry = match get_entry::<Arch>(
            root_level,
            self.paging_type,
            PageTableStateWithAddress::NotSelfMapped(self.base),
            SELF_MAP_INDEX,
        ) {
            Ok(entry) => entry,
            Err(_) => return PageTableState::ActiveIdentityMapped, // if we can't read the entry, assume identity mapped
        };

        if !self_map_entry.get_present_bit() || self_map_entry.get_next_address() != self.base {
            PageTableState::ActiveIdentityMapped
        } else {
            PageTableState::ActiveSelfMapped
        }
    }

    pub fn map_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> Result<(), PtError> {
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

    pub fn unmap_memory_region(&mut self, address: u64, size: u64) -> Result<(), PtError> {
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

    pub fn install_page_table(&mut self) -> Result<(), PtError> {
        // SAFETY: The page table structure should guarantee that the page table is correct.
        unsafe { Arch::install_page_table(self.base.into()) }
    }

    pub fn query_memory_region(&self, address: u64, size: u64) -> Result<MemoryAttributes, PtError> {
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

    pub fn dump_page_tables(&self, address: u64, size: u64) -> Result<(), PtError> {
        if self.validate_address_range(address.into(), size).is_err() {
            log::error!("Invalid address range for page table dump! Address: {address:#x?}, Size: {size:#x?}");
            return Err(PtError::InvalidMemoryRange);
        }

        let address = VirtualAddress::new(address);
        let start_va = address;
        let end_va = (address + (size - 1))?;

        log::info!("Page Table Range: {start_va} - {end_va}");
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

// This enum is used in get_table to determine the page table state and how to interpret the base address.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum PageTableStateWithAddress {
    /// The page table is installed and self-mapped. The VirtualAddress is the VA this table maps.
    SelfMapped(VirtualAddress),
    /// The page table may be installed but is not self-mapped. The PhysicalAddress is the base address of the page table.
    NotSelfMapped(PhysicalAddress),
}

/// Page table traversal function to get a mutable slice of the page table entries at the specified level
/// and paging type. This is the main function that jumps between page tables in an unsafe (but architecturally correct)
/// manner and returns a safe abstraction (a slice of page table entries) that can be used to manipulate the page table
/// entries for higher level code.
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers to the page table entries. This matches what the HW
/// does when accessing the page table entries and the entire rest of the module is designed to ensure that the page
/// table is valid and consistent before this function is called.
pub unsafe fn get_table<'a, T, Arch: PageTableHal>(
    level: PageLevel,
    paging_type: PagingType,
    state: PageTableStateWithAddress,
) -> &'a mut [T] {
    // the base depends on whether we are self-mapped or not. If we are self-mapped, the state contains the VA to use
    // to get the base of the page table. If we are not self-mapped, we use the physical address as the base.
    let base = match state {
        PageTableStateWithAddress::SelfMapped(virt) => Arch::get_self_mapped_base(level, virt, paging_type),
        PageTableStateWithAddress::NotSelfMapped(phys) => phys.into(),
    };

    // SAFETY: Architecturally, the page table is laid out as an array of entries of type T, and we are trusting that
    // the base address is valid and points to a page table of the correct type.
    unsafe { slice::from_raw_parts_mut(base as *mut T, Arch::MAX_ENTRIES) }
}

pub(crate) fn get_entry<'a, Arch: PageTableHal>(
    level: PageLevel,
    paging_type: PagingType,
    state: PageTableStateWithAddress,
    index: u64,
) -> Result<&'a mut Arch::PTE, PtError> {
    // SAFETY: We are using the page table as provided to the HW and are parsing it in the same manner as defined
    // by the architecture. This is inherently unsafe because we are trusting that the page table is valid. The
    // rest of the code in this module is designed to ensure that the page table is valid and consistent.
    let slice = unsafe { get_table::<Arch::PTE, Arch>(level, paging_type, state) };
    slice.get_mut(index as usize).ok_or(PtError::NoMapping)
}

#[derive(Debug, PartialEq)]
struct PageTableRange<'a, Arch: PageTableHal> {
    /// Physical page table base address
    slice: &'a mut [Arch::PTE],

    /// Page table's page level, not used but left here for debugability
    _level: PageLevel,
}

impl<'a, Arch: PageTableHal> PageTableRange<'a, Arch> {
    pub fn new(
        level: PageLevel,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        paging_type: PagingType,
        state: PageTableStateWithAddress,
    ) -> Result<Self, PtError> {
        // SAFETY: We are using the page table as provided to the HW and are parsing it in the same manner as defined
        // by the architecture. This is inherently unsafe because we are trusting that the page table is valid. The
        // rest of the code in this module is designed to ensure that the page table is valid and consistent.
        let slice = unsafe { get_table::<Arch::PTE, Arch>(level, paging_type, state) };
        let start = start_va.get_index(level) as usize;
        let end = end_va.get_index(level) as usize;
        if start_va > end_va || start > end || end >= slice.len() {
            log::error!(
                "Invalid page table range: start index {} > end index {} or out of bounds for level {:?}",
                start,
                end,
                level
            );
            return Err(PtError::InvalidMemoryRange);
        }
        Ok(Self { slice: &mut slice[start..=end], _level: level })
    }
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;
    use std::{
        alloc::{Layout, alloc_zeroed},
        sync::atomic::{AtomicBool, AtomicU64},
    };

    static ACTIVE: AtomicBool = AtomicBool::new(false);
    static BASE: AtomicU64 = AtomicU64::new(0);

    // Dummy Arch implementation for testing
    #[derive(PartialEq, Debug)]
    struct DummyArch;
    impl PageTableHal for DummyArch {
        type PTE = DummyPTE;
        const MAX_ENTRIES: usize = 512;
        const DEFAULT_ATTRIBUTES: MemoryAttributes = MemoryAttributes::empty();

        fn paging_type_supported(_paging_type: PagingType) -> Result<(), PtError> {
            Ok(())
        }
        fn get_self_mapped_base(_level: PageLevel, _va: VirtualAddress, _paging_type: PagingType) -> u64 {
            // for the test we can't use the real self map, so just return the PT base
            BASE.load(std::sync::atomic::Ordering::Relaxed)
        }
        fn get_zero_va(_paging_type: PagingType) -> Result<VirtualAddress, PtError> {
            Ok(VirtualAddress::new(0x1000))
        }
        fn get_max_va(_paging_type: PagingType) -> Result<VirtualAddress, PtError> {
            Ok(VirtualAddress::new(0xFFFF_FFFF_FFFF_0000))
        }
        fn is_table_active(_base: u64) -> bool {
            ACTIVE.load(std::sync::atomic::Ordering::Relaxed)
        }
        unsafe fn zero_page(_va: VirtualAddress) {}
        unsafe fn install_page_table(_base: u64) -> Result<(), PtError> {
            Ok(())
        }
        fn invalidate_tlb(_va: VirtualAddress) {}
        fn level_supports_pa_entry(_level: PageLevel) -> bool {
            true
        }
        fn invalidate_tlb_all() {}
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    struct DummyPTE(u64);

    impl DummyPTE {
        fn new() -> Self {
            Self(0)
        }
    }

    impl PageTableEntry for DummyPTE {
        fn get_present_bit(&self) -> bool {
            self.0 & 0x8000_0000_0000_0000 != 0
        }
        fn set_present_bit(&mut self, val: bool, _va: VirtualAddress) {
            if val {
                self.0 |= 0x8000_0000_0000_0000;
            } else {
                self.0 &= !0x8000_0000_0000_0000;
            }
        }
        fn points_to_pa(&self, level: PageLevel) -> bool {
            !matches!(level, PageLevel::Level4 | PageLevel::Level5)
        }
        fn get_next_address(&self) -> PhysicalAddress {
            PhysicalAddress::new(self.0 & 0x0000_FFFF_FFFF_F000)
        }
        fn update_fields(
            &mut self,
            attrs: MemoryAttributes,
            pa: PhysicalAddress,
            present: bool,
            _level: PageLevel,
            _va: VirtualAddress,
        ) -> Result<(), PtError> {
            let mut addr: u64 = pa.into();
            addr &= !0xFFF;
            self.0 = addr | attrs.bits() | if present { 0x8000_0000_0000_0000 } else { 0 };
            Ok(())
        }
        fn get_attributes(&self) -> MemoryAttributes {
            MemoryAttributes::from_bits_truncate(self.0 & 0x0000_0000_0000_0FFF)
        }
        fn dump_entry(&self, _va: VirtualAddress, _level: PageLevel) -> Result<(), PtError> {
            Ok(())
        }
        fn entry_ptr_address(&self) -> u64 {
            self as *const Self as u64
        }
        fn dump_entry_header() {
            // Dummy implementation for test
            println!("DummyPTE Header");
        }
        fn unmap(&mut self, _va: VirtualAddress) {
            self.0 = 0;
        }
    }

    // Dummy PageAllocator for testing
    #[derive(Clone, Debug)]
    struct DummyAllocator {
        allocated_pages: std::rc::Rc<std::cell::RefCell<Vec<u64>>>,
    }
    impl DummyAllocator {
        fn new() -> Self {
            Self { allocated_pages: std::rc::Rc::new(std::cell::RefCell::new(Vec::new())) }
        }

        fn cleanup(&self) {
            let pages = self.allocated_pages.borrow_mut();
            let layout = Layout::from_size_align(PAGE_SIZE as usize, PAGE_SIZE as usize).unwrap();
            for &page_addr in pages.iter() {
                unsafe {
                    std::alloc::dealloc(page_addr as *mut u8, layout);
                }
            }
        }
    }
    impl PageAllocator for DummyAllocator {
        fn allocate_page(&mut self, _size: u64, _align: u64, is_root: bool) -> Result<u64, PtError> {
            let layout = Layout::from_size_align(PAGE_SIZE as usize, PAGE_SIZE as usize).unwrap();
            let ptr = unsafe { alloc_zeroed(layout) };
            if ptr.is_null() {
                return Err(PtError::InvalidMemoryRange);
            }

            let addr = ptr as u64;
            self.allocated_pages.borrow_mut().push(addr);

            if is_root {
                BASE.store(addr, std::sync::atomic::Ordering::Relaxed);
            }

            Ok(addr)
        }
    }

    fn make_table() -> (PageTableInternal<DummyAllocator, DummyArch>, DummyAllocator) {
        let allocator = DummyAllocator::new();
        let allocator_clone = allocator.clone();
        let pt = PageTableInternal::new(allocator, PagingType::Paging4Level).unwrap();
        (pt, allocator_clone)
    }

    #[test]
    fn test_get_state_variants() {
        let (pt, allocator) = make_table();

        // Cleanup function to ensure memory is freed
        let cleanup = || {
            allocator.cleanup();
        };

        // By default, the table is not active, so should be Inactive
        ACTIVE.store(false, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(pt.get_state(), PageTableState::Inactive);

        // Set table as active, but self-map entry is not present or doesn't match base
        ACTIVE.store(true, std::sync::atomic::Ordering::Relaxed);

        // Overwrite the self-map entry to not present
        let root_level = PageLevel::root_level(pt.paging_type);
        let entry = get_entry::<DummyArch>(
            root_level,
            pt.paging_type,
            PageTableStateWithAddress::NotSelfMapped(pt.base),
            SELF_MAP_INDEX,
        )
        .unwrap();
        entry.set_present_bit(false, VirtualAddress::new(0));

        assert_eq!(pt.get_state(), PageTableState::ActiveIdentityMapped);

        // Now set the self-map entry to present and point to the correct base
        entry.set_present_bit(true, VirtualAddress::new(0));
        entry.update_fields(DummyArch::DEFAULT_ATTRIBUTES, pt.base, true, root_level, VirtualAddress::new(0)).unwrap();

        assert_eq!(pt.get_state(), PageTableState::ActiveSelfMapped);

        cleanup();
    }

    #[test]
    fn test_validate_address_range() {
        let (pt, allocator) = make_table();

        assert!(pt.validate_address_range(VirtualAddress::new(0x1000), 0x2000).is_ok());
        assert_eq!(pt.validate_address_range(VirtualAddress::new(0x1001), 0x2000), Err(PtError::UnalignedAddress));
        assert_eq!(pt.validate_address_range(VirtualAddress::new(0x1000), 0), Err(PtError::InvalidMemoryRange));
        assert_eq!(pt.validate_address_range(VirtualAddress::new(0x1000), 0x1234), Err(PtError::UnalignedMemoryRange));

        allocator.cleanup();
    }

    #[test]
    fn test_allocate_page_alignment() {
        let (mut pt, allocator) = make_table();
        let pa: u64 = pt.allocate_page(PageTableState::Inactive).unwrap().into();
        assert_eq!(pa % PAGE_SIZE, 0);

        allocator.cleanup();
    }

    #[test]
    fn test_split_large_page_error() {
        let (mut pt, allocator) = make_table();
        let mut entry = DummyPTE::new();
        entry.set_present_bit(false, VirtualAddress::new(0x0));
        let res =
            pt.split_large_page(VirtualAddress::new(0x0), &mut entry, PageTableState::Inactive, PageLevel::Level1);
        assert_eq!(res, Err(PtError::InvalidParameter));

        allocator.cleanup();
    }

    #[test]
    fn test_page_table_range_invalid() {
        // Allocate a page-aligned, page-length structure and use its address as the base
        let layout = std::alloc::Layout::from_size_align(PAGE_SIZE as usize, PAGE_SIZE as usize).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null());
        let base_pa = PhysicalAddress::new(ptr as u64);

        let res = PageTableRange::<DummyArch>::new(
            PageLevel::Level1,
            VirtualAddress::new(3),
            VirtualAddress::new(2),
            PagingType::Paging4Level,
            PageTableStateWithAddress::NotSelfMapped(base_pa),
        );
        assert_eq!(res, Err(PtError::InvalidMemoryRange));

        // Clean up the manually allocated memory
        unsafe {
            std::alloc::dealloc(ptr, layout);
        }
    }

    #[test]
    fn test_dump_page_tables_invalid_range() {
        let (pt, allocator) = make_table();
        let res = pt.dump_page_tables(0x1001, 0x1000);
        assert_eq!(res, Err(PtError::InvalidMemoryRange));

        allocator.cleanup();
    }

    #[test]
    fn test_from_existing_unaligned() {
        let allocator = DummyAllocator::new();
        let res = unsafe {
            PageTableInternal::<DummyAllocator, DummyArch>::from_existing(
                0x123,
                allocator.clone(),
                PagingType::Paging4Level,
            )
        };
        assert!(matches!(res, Err(PtError::UnalignedPageBase)));

        allocator.cleanup();
    }

    #[test]
    fn test_map_memory_region_top_va_overflow() {
        let (mut pt, allocator) = make_table();
        // max_va is 0xFFFF_FFFF_FFFF_0000, so use an address near the top and a size that overflows
        let addr = 0xFFFF_FFFF_FFFF_0000;
        let size = 0x2000; // This will make top_va > max_va
        let res = pt.map_memory_region(addr, size, MemoryAttributes::empty());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));

        allocator.cleanup();
    }

    #[test]
    fn test_unmap_memory_region_top_va_overflow() {
        let (mut pt, allocator) = make_table();
        let addr = 0xFFFF_FFFF_FFFF_0000;
        let size = 0x2000;
        let res = pt.unmap_memory_region(addr, size);
        assert_eq!(res, Err(PtError::InvalidMemoryRange));

        allocator.cleanup();
    }
}
