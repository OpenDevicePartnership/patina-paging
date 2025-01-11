///
/// Implements x64 paging. Supports below modes
/// - x64 4KB 5 level paging
/// - x64 4KB 4 level paging
///
use super::{
    pagetablestore::{X64PageTableEntry, X64PageTableStore},
    reg::{invalidate_tlb, write_cr3},
    structs::{PageLevel, PhysicalAddress, VirtualAddress, MAX_PML4_VA, MAX_PML5_VA, PAGE_SIZE},
};
use crate::{page_allocator::PageAllocator, MemoryAttributes, PageTable, PagingType, PtError, PtResult};
use core::ptr;

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
        let base = page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, true)?;

        // SAFETY: We just allocated the page, so it is safe to use it.
        // We always need to zero any pages, as our contract with the page_allocator does not specify that we will
        // get zeroed pages. Random data in the page could confuse this code and make us believe there are existing
        // entries in the page table.
        unsafe { ptr::write_bytes(base as *mut u8, 0, PAGE_SIZE as usize) };
        assert!(PhysicalAddress::new(base).is_4kb_aligned());

        // SAFETY: We just allocated the page, so it is safe to use it.
        unsafe { Self::from_existing(base, page_allocator, paging_type) }
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

        Ok(Self { base, page_allocator, paging_type, highest_page_level, lowest_page_level })
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
        unsafe { ptr::write_bytes(base as *mut u8, 0, PAGE_SIZE as usize) };
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
        attributes: MemoryAttributes,
    ) -> PtResult<()> {
        let mut va = start_va;

        let table = X64PageTableStore::new(base, level, self.paging_type, start_va, end_va);

        for mut entry in table {
            if !entry.present()
                && level.supports_pa_entry()
                && va.is_level_aligned(level)
                && u64::from(end_va) - u64::from(va) + 1 >= level.entry_va_size()
            {
                if level == self.lowest_page_level {
                    log::info!("Created Large Page Mapping at {}: {} - {}", level, va, end_va);
                }
                // This entry is large enough to be a whole entry for this supporting level,
                // so we can map the whole range in one go.
                entry.update_fields(attributes, va.into(), true)?;
            } else {
                assert!(level != self.lowest_page_level);
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

        let table = X64PageTableStore::new(base, level, self.paging_type, start_va, end_va);
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

        let table = X64PageTableStore::new(base, level, self.paging_type, start_va, end_va);

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
        prev_attributes: &mut MemoryAttributes,
    ) -> PtResult<MemoryAttributes> {
        let mut va = start_va;

        let table = X64PageTableStore::new(base, level, self.paging_type, start_va, end_va);
        for entry in table {
            if !entry.present() {
                return Err(PtError::NoMapping);
            }

            if entry.points_to_pa() {
                let current_attributes = entry.get_attributes();
                if (*prev_attributes).is_empty() {
                    *prev_attributes = current_attributes;
                }

                if *prev_attributes != current_attributes {
                    return Err(PtError::IncompatibleMemoryAttributes);
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

                self.query_memory_region_internal(
                    next_level_start_va,
                    next_level_end_va,
                    (level as u64 - 1).into(),
                    next_base,
                    prev_attributes,
                )?;
            }
            va = va.get_next_va(level);
        }

        Ok(*prev_attributes)
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

        log::info!(
            "Splitting large page: {} - {}",
            VirtualAddress::new(large_page_start),
            VirtualAddress::new(large_page_end)
        );

        let attributes = entry.get_attributes();

        if level == self.lowest_page_level || !entry.points_to_pa() {
            return Err(PtError::InvalidParameter);
        }

        let pa = self.allocate_page()?;
        self.map_memory_region_internal(
            large_page_start.into(),
            large_page_end.into(),
            (level as u64 - 1).into(),
            pa,
            attributes,
        )?;

        entry.update_fields(MemoryAttributes::empty(), pa, false)
    }

    fn dump_page_tables_internal(
        &self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        base: PhysicalAddress,
    ) {
        let mut va = start_va;

        let table = X64PageTableStore::new(base, level, self.paging_type, start_va, end_va);
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
        // Overflow check
        address.try_add(size)?;

        // Check the memory range
        match self.paging_type {
            PagingType::Paging5Level => {
                if address + size > VirtualAddress::new(MAX_PML5_VA) {
                    return Err(PtError::InvalidMemoryRange);
                }
            }
            PagingType::Paging4Level => {
                if address + size > VirtualAddress::new(MAX_PML4_VA) {
                    return Err(PtError::InvalidMemoryRange);
                }
            }
            _ => return Err(PtError::InvalidParameter),
        }

        match self.paging_type {
            PagingType::Paging5Level | PagingType::Paging4Level => {
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
    type ALLOCATOR = A;

    fn borrow_allocator(&mut self) -> &mut A {
        self.borrow_allocator()
    }

    fn map_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()> {
        let address = VirtualAddress::new(address);
        log::info!("map_memory_region: {} size: {}", address, size);

        self.validate_address_range(address, size)?;

        // We map until next alignment
        let start_va = address;
        let end_va = address + size - 1;

        let result = self.map_memory_region_internal(start_va, end_va, self.highest_page_level, self.base, attributes);

        unsafe { invalidate_tlb(self.base.into()) };

        result
    }

    fn unmap_memory_region(&mut self, address: u64, size: u64) -> PtResult<()> {
        log::info!("unmap_memory_region: {} size: {}", address, size);
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + size - 1;

        let result = self.unmap_memory_region_internal(start_va, end_va, self.highest_page_level, self.base);

        unsafe { invalidate_tlb(self.base.into()) };

        result
    }

    fn remap_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()> {
        log::info!("remap_memory_region: {} size: {}", address, size);
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + size - 1;

        // make sure the memory region has same attributes set
        let mut prev_attributes = MemoryAttributes::empty();
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

    fn query_memory_region(&self, address: u64, size: u64) -> PtResult<MemoryAttributes> {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size)?;

        let start_va = address;
        let end_va = address + size - 1;

        let mut prev_attributes = MemoryAttributes::empty();
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

    fn get_page_table_pages_for_size(&self, address: u64, size: u64) -> PtResult<u64> {
        num_page_tables_required(address, size, self.paging_type)
    }
}

/// Given the [start, end offset] at the current level from the [start, end VA],
/// this function calculates the number of entries required for the range. It
/// considers the number of entries at the parent level because the start and
/// end offsets might span across multiple pages.
fn find_num_entries(start_offset: u64, end_offset: u64, num_entries_at_parent_level: u64) -> u64 {
    let mut num_entries = 0;

    // Entries spanning multiple pages
    if num_entries_at_parent_level > 1 {
        num_entries += 512 - start_offset; // Number of upper entries in first page
        num_entries += (num_entries_at_parent_level - 2) * 512; // number of entries in between pages
        num_entries += end_offset + 1; // Number of lower entries in the last page
    } else {
        // Entries do not span multiple pages(end_offset is guaranteed to be higher than start offset)
        num_entries = end_offset - start_offset + 1; // Number of entries in the page
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

    if !level.supports_pa_entry() {
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
    log::info!(
        "aligned_address: {:#x}, aligned_end: {:#x} from address: {:#x} size: {:#x}",
        aligned_address,
        aligned_end,
        address,
        size
    );
    let num_large_pages = (aligned_end - aligned_address) / alignment;
    let page_entries: u64 = 512;
    let remaining_levels = level as u64 - lowest_page_level as u64;
    log::info!("level: {} num_large_pages: {},  remaining_levels: {}", level, num_large_pages, remaining_levels,);
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

    // For the given paging type, identify the highest and lowest page levels.
    // This is used during page building to terminate the recursion.
    let (highest_page_level, lowest_page_level) = match paging_type {
        PagingType::Paging5Level => (PageLevel::Pml5, PageLevel::Pt),
        PagingType::Paging4Level => (PageLevel::Pml4, PageLevel::Pt),
        _ => return Err(PtError::InvalidParameter),
    };

    let mut num_entries_at_parent_level = 0;
    let mut num_tables_at_current_level = 1; // top level table
    let mut total_num_tables = 0;

    // Rust does not support creating ranges [high..=low], so we use
    // [low..=high].rev() instead.
    for level in ((lowest_page_level as u64)..=(highest_page_level as u64)).rev() {
        // Add the number of tables required at the current level to the total
        // pages. This has already been computed in the previous iteration.
        total_num_tables += num_tables_at_current_level;

        let start_offset = start_va.get_index(level.into());
        let end_offset = end_va.get_index(level.into());

        // Prepare for the next level: Calculating the number of tables required
        // at the next level (e.g., PDP) depends on the number of entries
        // present at the current level (e.g., PML4). Calculating the number of
        // entries at the current level (PML4) in turn depends on the number of
        // entries at the parent level (PML5 — this is the third parameter).
        // Why? See below.

        //  |  parent level |  current level |  next level
        //  |               |                |
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
        let num_entries_at_current_level = find_num_entries(start_offset, end_offset, num_entries_at_parent_level);

        // These are truely consumed in the next iteration.
        num_tables_at_current_level = num_entries_at_current_level;
        num_entries_at_parent_level = num_entries_at_current_level;
    }

    // The above calculates only the lowest pages, now calculate saving through large
    // pages.
    let savings = find_large_page_savings(address.into(), size, highest_page_level, lowest_page_level);
    log::info!("total: {} savings {}", total_num_tables, savings);
    total_num_tables -= savings;

    Ok(total_num_tables)
}
