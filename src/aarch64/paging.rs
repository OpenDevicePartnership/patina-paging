use super::{
    pagetablestore::AArch64PageTableStore,
    reg,
    structs::{PageLevel, PhysicalAddress, VirtualAddress, MAX_VA, PAGE_SIZE},
};
use crate::{page_allocator::PageAllocator, MemoryAttributes, PageTable, PagingType, PtError, PtResult};
use core::ptr;
use mu_pi::protocols::cpu_arch::CpuFlushType;
use uefi_sdk::base::{SIZE_16TB, SIZE_1TB, SIZE_256TB, SIZE_4GB, SIZE_4TB, SIZE_64GB};

const MAX_VA_BITS: u64 = 48;

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
                CpuFlushType::EfiCpuFlushTypeWriteBack,
            );
        }

        let base = page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, true)?;
        if !reg::is_mmu_enabled() {
            reg::cache_range_operation(base, PAGE_SIZE, CpuFlushType::EFiCpuFlushTypeInvalidate);
        }

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
        let base = self.page_allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, false)?;
        if !reg::is_mmu_enabled() {
            reg::cache_range_operation(base, PAGE_SIZE, CpuFlushType::EFiCpuFlushTypeInvalidate);
        }

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
                if reg::is_this_page_table_active(self.base) {
                    // Need to do the heavy duty break-before-make sequence
                    let _val = entry.update_shadow_fields(attributes, va.into());
                    #[cfg(all(not(test), target_arch = "aarch64"))]
                    unsafe {
                        reg::replace_live_xlat_entry(entry.raw_address(), _val, va.into());
                    }
                } else {
                    // Just update the entry and flush TLB
                    entry.update_fields(attributes, va.into())?;
                    reg::update_translation_table_entry(entry.raw_address(), va.into());
                }

                // get max va addressable by current entry
                va = va.get_next_va(level);
            }
            return Ok(());
        }

        for mut entry in table {
            if !entry.is_valid() {
                let pa = self.allocate_page()?;

                if reg::is_this_page_table_active(self.base) {
                    // Need to do the heavy duty break-before-make sequence
                    let _val = entry.update_shadow_fields(attributes, pa);
                    #[cfg(all(not(test), target_arch = "aarch64"))]
                    unsafe {
                        reg::replace_live_xlat_entry(entry.raw_address(), _val, pa.into());
                    }
                } else {
                    // Just update the entry and flush TLB
                    entry.update_fields(attributes, pa)?;
                    reg::update_translation_table_entry(entry.raw_address(), pa.into());
                }
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

                if reg::is_this_page_table_active(self.base) {
                    // Need to do the heavy duty break-before-make sequence
                    let _val = entry.update_shadow_fields(attributes, va.into());
                    #[cfg(all(not(test), target_arch = "aarch64"))]
                    unsafe {
                        reg::replace_live_xlat_entry(entry.raw_address(), _val, va.into());
                    }
                } else {
                    // Just update the entry and flush TLB
                    entry.update_fields(attributes, va.into())?;
                    reg::update_translation_table_entry(entry.raw_address(), va.into());
                }

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
                // start of the next level va. It will be same as current va
                let next_level_start_va = va;

                // get max va addressable by current entry
                let curr_va_ceil = va.round_up(level);

                // end of next level va. It will be minimum of next va and end va
                let next_level_end_va = VirtualAddress::min(curr_va_ceil, end_va);

                let l: u64 = level.into();
                let range = format!("{}[{} {}]", "  ".repeat(5 - l as usize), next_level_start_va, next_level_end_va);
                log::info!("{}|{:48}{}", level, range, entry.dump_entry());

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
            log::info!("{}|{:48}{}", level, range, entry.dump_entry());

            self.dump_page_tables_internal(
                next_level_start_va,
                next_level_end_va,
                (level as u64 - 1).into(),
                next_base,
            );

            va = va.get_next_va(level);
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

        let pa_bits = reg::get_phys_addr_bits();
        //
        // Limit the virtual address space to what we can actually use: core
        // mandates a 1:1 mapping, so no point in making the virtual address
        // space larger than the physical address space. We also have to take
        // into account the architectural limitations that result from firmware's
        // use of 4 KB pages.
        //
        let max_address_bits = core::cmp::min(pa_bits, MAX_VA_BITS);
        let max_address = (1 << max_address_bits) - 1;

        let t0sz = 64 - max_address_bits;
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
            panic!("mu-paging is only expected to run at EL2 and EL1, not EL3.");
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
            reg::cache_range_operation(self.base.into(), root_table_cnt * 8, CpuFlushType::EFiCpuFlushTypeInvalidate);
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

    fn dump_page_tables(&self, address: u64, size: u64) {
        let address = VirtualAddress::new(address);

        self.validate_address_range(address, size).unwrap();

        let start_va = address;
        let end_va = address + size - 1;

        log::info!("start-end:[{} {}]", start_va, end_va);
        log::info!("{}", "-".repeat(130));
        self.dump_page_tables_internal(start_va, end_va, self.highest_page_level, self.base)
    }

    fn get_page_table_pages_for_size(&self, _address: u64, _size: u64) -> PtResult<u64> {
        num_page_tables_required(_address, _size, self.paging_type)
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

    Ok(total_num_tables)
}

fn get_root_table_count(t0sz: u64) -> u64 {
    512 >> ((t0sz - 16) % 9)
}
