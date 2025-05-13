///
/// Implements x64 paging. Supports below modes
/// - x64 4KB 5 level paging
/// - x64 4KB 4 level paging
///
use super::{
    pagetablestore::{invalidate_self_map_va, X64PageTableEntry, X64PageTableStore},
    reg::{invalidate_tlb, write_cr3, zero_page},
    structs::*,
};
use crate::{
    page_allocator::PageAllocator, MemoryAttributes, PageTable, PagingType, PtError, PtResult, RangeMappingState,
};
use core::arch::asm;

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
    zero_va_pt_pa: Option<PhysicalAddress>,
}

impl<A: PageAllocator> X64PageTable<A> {
    pub fn new(mut page_allocator: A, paging_type: PagingType) -> PtResult<Self> {
        // Allocate the top level page table(PML5)
        let base = page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, true)?;
        assert!(PhysicalAddress::new(base).is_4kb_aligned());

        // SAFETY: We just allocated the page, so it is safe to use it.
        // We always need to zero any pages, as our contract with the page_allocator does not specify that we will
        // get zeroed pages. Random data in the page could confuse this code and make us believe there are existing
        // entries in the page table.

        // we have not installed this page table, we can't use our VA range to zero page or
        // rely on self-map, so we have to rely on the identity mapping for the root page
        unsafe { zero_page(base) };

        // allocate the pages to map the zero VA range and zero them
        let pa_array = [
            page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, false)?,
            page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, false)?,
            page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, false)?,
            page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, false)?,
        ];

        pa_array.iter().for_each(|pa| {
            unsafe { zero_page(*pa) };
        });

        let pa_array: [PhysicalAddress; 4] = pa_array.map(Into::into);

        // SAFETY: We just allocated the page, so it is safe to use it.
        match unsafe { Self::from_existing(base, page_allocator, paging_type) } {
            Ok(mut pt) => {
                // we choose the penultimate PML[4|5] entry to use as the zeroing range and the last PML[4|5] entry for
                // the self-map entry. We need to map down to the 4k page for the zero page
                let (level, zero_va) = match pt.paging_type {
                    PagingType::Paging5Level => (PageLevel::Pml5, ZERO_VA_5_LEVEL),
                    PagingType::Paging4Level => (PageLevel::Pml4, ZERO_VA_4_LEVEL),
                    _ => return Err(PtError::InvalidParameter),
                };

                // create our self-map entry as the final entry
                let mut self_map_entry =
                    X64PageTableEntry::new(pt.base, SELF_MAP_INDEX, level, pt.paging_type, pt.base.into(), false);

                // create it with permissive attributes
                self_map_entry.update_fields(MemoryAttributes::empty(), pt.base, false)?;

                // now set up the zero VA range so that we can zero pages before installing them in the page table
                // this will be at index 0x1FE for the top level page table.
                let mut pml4_index = ZERO_VA_INDEX;
                let mut pml4_base = pt.base;
                if pt.paging_type == PagingType::Paging5Level {
                    // assign PA to the penultimate PML5 entry
                    let mut last_pml5_entry = X64PageTableEntry::new(
                        pt.base,
                        ZERO_VA_INDEX,
                        PageLevel::Pml5,
                        pt.paging_type,
                        VirtualAddress::new(zero_va),
                        false,
                    );
                    last_pml5_entry.update_fields(MemoryAttributes::empty(), pa_array[3], false)?;
                    pml4_index = 0;
                    pml4_base = pa_array[3];
                }

                // assign PA to the penultimate PML4 entry if 4 level paging, otherwise to the first index
                let mut second_last_pml4_entry = X64PageTableEntry::new(
                    pml4_base,
                    pml4_index,
                    PageLevel::Pml4,
                    pt.paging_type,
                    VirtualAddress::new(zero_va),
                    false,
                );
                second_last_pml4_entry.update_fields(MemoryAttributes::empty(), pa_array[0], false)?;

                // set up the PDP entry
                let mut pdp_entry = X64PageTableEntry::new(
                    pa_array[0],
                    0,
                    PageLevel::Pdp,
                    pt.paging_type,
                    VirtualAddress::new(zero_va),
                    false,
                );
                pdp_entry.update_fields(MemoryAttributes::empty(), pa_array[1], false)?;

                // set up the PD entry next
                let mut pd_entry = X64PageTableEntry::new(
                    pa_array[1],
                    0,
                    PageLevel::Pd,
                    pt.paging_type,
                    VirtualAddress::new(zero_va),
                    false,
                );
                pd_entry.update_fields(MemoryAttributes::empty(), pa_array[2], false)?;

                // set up an invalid PT entry that will get overridden by each page we allocate
                let mut pt_entry = X64PageTableEntry::new(
                    pa_array[2],
                    0,
                    PageLevel::Pt,
                    pt.paging_type,
                    VirtualAddress::new(zero_va),
                    false,
                );
                pt_entry.update_fields(MemoryAttributes::empty(), PhysicalAddress::new(0), true)?;
                pt_entry.set_present(false);

                pt.zero_va_pt_pa = Some(pa_array[2]);
                Ok(pt)
            }
            Err(e) => Err(e),
        }
    }

    pub fn borrow_allocator(&mut self) -> &mut A {
        &mut self.page_allocator
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
            PagingType::Paging5Level => (PageLevel::Pml5, PageLevel::Pt),
            PagingType::Paging4Level => (PageLevel::Pml4, PageLevel::Pt),
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

        // SAFETY: We just allocated the page, so it is safe to use it.
        // We always need to zero any pages, as our contract with the page_allocator does not specify that we will
        // get zeroed pages. Random data in the page could confuse this code and make us believe there are existing
        // entries in the page table.
        let zero_va = match self.is_installed_and_self_mapped() {
            true => {
                let va = match self.paging_type {
                    PagingType::Paging5Level => ZERO_VA_5_LEVEL,
                    PagingType::Paging4Level => ZERO_VA_4_LEVEL,
                    _ => return Err(PtError::InvalidParameter),
                };

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
                let mut zero_entry = X64PageTableEntry::new(
                    zero_va_pt_pa,
                    0,
                    PageLevel::Pt,
                    self.paging_type,
                    VirtualAddress::new(va),
                    true,
                );

                zero_entry.update_fields(
                    MemoryAttributes::empty() | MemoryAttributes::ExecuteProtect,
                    PhysicalAddress::new(base),
                    true,
                )?;

                // invalidate the TLB entry for the zero VA to ensure we are zeroing our newly placed page
                unsafe { asm!("mfence", "invlpg [{}]", in(reg) va) };

                va
            }
            // If we have not installed this page table, we can't use our VA range to zero pages yet and have to go on
            // the assumption that the caller has this page mapped
            false => base,
        };

        unsafe { zero_page(zero_va) };
        let base = PhysicalAddress::new(base);
        if !base.is_4kb_aligned() {
            return Err(PtError::UnalignedPageBase);
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
        attributes: MemoryAttributes,
    ) -> PtResult<()> {
        let mut va = start_va;

        let table = X64PageTableStore::new(
            base,
            level,
            self.paging_type,
            start_va,
            end_va,
            self.is_installed_and_self_mapped(),
        );

        for mut entry in table {
            if !entry.present()
                && level.supports_pa_entry()
                && va.is_level_aligned(level)
                && va.length_through(end_va) >= level.entry_va_size()
            {
                // This entry is large enough to be a whole entry for this supporting level,
                // so we can map the whole range in one go.
                entry.update_fields(attributes, va.into(), true)?;
            } else {
                if level == self.lowest_page_level {
                    // We are trying to map a page but it is already mapped. The caller has an inconsistent state
                    // of the page table
                    log::error!(
                        "Paging crate failed to map memory region at VA {:#x?} as the entry is already valid",
                        va
                    );
                    return Err(PtError::InconsistentMappingAcrossRange);
                }
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

        let table = X64PageTableStore::new(
            base,
            level,
            self.paging_type,
            start_va,
            end_va,
            self.is_installed_and_self_mapped(),
        );
        for mut entry in table {
            // Check if this is a large page in need of splitting.
            if entry.points_to_pa()
                && (!va.is_level_aligned(level) || va.length_through(end_va) < level.entry_va_size())
            {
                self.split_large_page(va, &mut entry)?;
            }

            if entry.present() {
                if entry.points_to_pa() {
                    entry.set_present(false);
                } else {
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

        let table = X64PageTableStore::new(
            base,
            level,
            self.paging_type,
            start_va,
            end_va,
            self.is_installed_and_self_mapped(),
        );

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

        let table = X64PageTableStore::new(
            base,
            level,
            self.paging_type,
            start_va,
            end_va,
            self.is_installed_and_self_mapped(),
        );
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
    fn split_large_page(&mut self, va: VirtualAddress, entry: &mut X64PageTableEntry) -> PtResult<()> {
        let level = entry.get_level();
        debug_assert!(level != self.lowest_page_level && entry.points_to_pa());

        // Round down to the nearest page boundary at the current level.
        let large_page_start: u64 = va.into();
        let large_page_start = large_page_start & !(level.entry_va_size() - 1);
        let large_page_end: u64 = large_page_start + level.entry_va_size() - 1;

        if level == self.lowest_page_level || !entry.points_to_pa() {
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
        let table = X64PageTableStore::new(
            pa,
            level - 1,
            self.paging_type,
            large_page_start.into(),
            large_page_end.into(),
            true,
        );

        if let Some(tb_entry) = table.into_iter().next() {
            invalidate_self_map_va(tb_entry.raw_address());
        }

        self.map_memory_region_internal(
            large_page_start.into(),
            large_page_end.into(),
            (level as u64 - 1).into(),
            pa,
            attributes,
        )
    }

    fn dump_page_tables_internal(
        &self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
    ) {
        let mut va = start_va;

        let table = X64PageTableStore::new(
            base,
            level,
            self.paging_type,
            start_va,
            end_va,
            self.is_installed_and_self_mapped(),
        );
        for entry in table {
            if !entry.present() && level != self.lowest_page_level {
                return;
            }

            // split the va range appropriately for the next level pages

            // start of the next level va. It will be same as current va
            let next_level_start_va = va;

            // get max va addressable by current entry
            let curr_va_ceil = va.round_up(level);

            // end of next level va. It will be minimum of next va and end va
            let next_level_end_va = VirtualAddress::min(curr_va_ceil, end_va);

            let l: u64 = level.into();
            let range = format!("{}[{} {}]", "  ".repeat(5 - l as usize), next_level_start_va, next_level_end_va);
            log::info!("{}|{:48}{}", level, range, entry.dump_entry());

            if entry.present() && !entry.points_to_pa() {
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

        let max_va = match self.paging_type {
            PagingType::Paging5Level => VirtualAddress::new(MAX_VA_5_LEVEL),
            PagingType::Paging4Level => VirtualAddress::new(MAX_VA_4_LEVEL),
            _ => return Err(PtError::InvalidParameter),
        };

        if address + size - 1 > max_va {
            return Err(PtError::InvalidMemoryRange);
        }

        // Overflow check, size is 0-based
        address.try_add(size - 1)?;

        match self.paging_type {
            PagingType::Paging5Level | PagingType::Paging4Level => {
                if size == 0 || !address.is_4kb_aligned() {
                    return Err(PtError::UnalignedAddress);
                }

                // Check the memory range is aligned
                if !VirtualAddress::new(size).is_4kb_aligned() {
                    return Err(PtError::UnalignedMemoryRange);
                }
            }
            _ => return Err(PtError::InvalidParameter),
        }

        Ok(())
    }

    /// Check if the page table is installed and self-mapped.
    /// This is used to determine if we can use the self-map to zero pages and reference the page table pages.
    /// If our page table base is not in cr3, self-mapped entries won't work for this page table. Similarly, if the
    /// expected self-map entry is not present or does not point to the page table base, we can't use the self-map.
    fn is_installed_and_self_mapped(&self) -> bool {
        let cr3 = unsafe { crate::x64::reg::read_cr3() };
        if cr3 != self.base.into() {
            return false;
        }

        // this is always read from the physical address of the page table, because we are trying to determine whether
        // we are self-mapped or not
        let self_map_entry = X64PageTableEntry::new(
            self.base,
            SELF_MAP_INDEX,
            self.highest_page_level,
            self.paging_type,
            self.base.into(),
            false,
        );

        if !self_map_entry.present() || self_map_entry.get_canonical_page_table_base() != self.base {
            return false;
        }

        true
    }
}

impl<A: PageAllocator> PageTable for X64PageTable<A> {
    type ALLOCATOR = A;

    fn borrow_allocator(&mut self) -> &mut A {
        self.borrow_allocator()
    }

    fn map_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        // We map until next alignment
        let start_va = address;
        let end_va = address + size - 1;

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

    fn remap_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + size - 1;

        // make sure the memory region has same attributes set
        let mut prev_attributes = RangeMappingState::Uninitialized;
        self.query_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, &mut prev_attributes)?;

        let result =
            self.remap_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, attributes);

        unsafe { invalidate_tlb(self.base.into()) };

        result
    }

    fn install_page_table(&mut self) -> PtResult<()> {
        let value: u64 = self.base.into();
        unsafe { write_cr3(value) };

        Ok(())
    }

    fn query_memory_region(&self, address: u64, size: u64) -> PtResult<MemoryAttributes> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + (size - 1);

        let mut prev_attributes = RangeMappingState::Uninitialized;
        self.query_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, &mut prev_attributes)
    }

    fn dump_page_tables(&self, address: u64, size: u64) {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size).unwrap();

        let start_va = address;
        let end_va = address + size - 1;

        log::info!("{}[{} {}]{}", "-".repeat(45), start_va, end_va, "-".repeat(48));
        log::info!("                                                      6362        52 51                                   12 11 9 8 7 6 5 4 3 2 1 0 ");
        log::info!("                                                      |N|           |                                        |   |M|P|I| |P|P|U|R| |");
        log::info!("                                                      |X| Available |     Page-Map Level-4 Base Address      |AVL|B|G|G|A|C|W|/|/|P|");
        log::info!("                                                      | |           |                                        |   |Z|S|N| |D|T|S|W| |");
        log::info!("{}", "-".repeat(132));
        // uses current cr3 base
        self.dump_page_tables_internal(start_va, end_va, self.highest_page_level, self.base);
        log::info!("{}", "-".repeat(132));
    }
}
