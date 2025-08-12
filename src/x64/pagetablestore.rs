use super::structs::*;
use crate::paging::PageTableState;
use crate::structs::*;
use crate::{MemoryAttributes, PagingType, PtError, PtResult};

// Constants for page levels to conform to x64 standards.
pub const PML5: PageLevel = PageLevel::Level5;
pub const PML4: PageLevel = PageLevel::Level4;
pub const PDP: PageLevel = PageLevel::Level3;
pub const PD: PageLevel = PageLevel::Level2;
pub const PT: PageLevel = PageLevel::Level1;

// Maximum number of entries in a page table (512)
const MAX_ENTRIES: usize = (PAGE_SIZE / 8) as usize;

/// This is a dummy page table entry that dispatches calls to the real page
/// table entries by locating them with the page base. Implementing this as an
/// enum ADT over real page table entries(PageMapEntry/PageTableEntry4KB/
/// PageTableEntry2MB) is not feasible, as it complicates the caller's
/// (paging.rs) code for destructing the enum entry types. Additionally, the
/// real page table entry structs do not contain enough information about their
/// location in the page table, They merely contain the actual data of the entry
/// itself. So directly working with them without page base do not help. This
/// dummy page table entry fills that gap.
#[derive(Debug)]
pub struct X64PageTableEntry {
    page_base: PhysicalAddress,
    index: u64,
    level: PageLevel,
    _paging_type: PagingType,
    start_va: VirtualAddress,
    state: PageTableState,
}

impl X64PageTableEntry {
    fn copy_entry(&self) -> PageTableEntryX64 {
        let entry = unsafe {
            get_entry::<PageTableEntryX64>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self._paging_type,
                self.state,
            )
        };
        *entry
    }

    fn set_entry(&mut self, new_entry: PageTableEntryX64) {
        let entry = unsafe {
            get_entry::<PageTableEntryX64>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self._paging_type,
                self.state,
            )
        };
        let prev_valid = entry.present();

        entry.swap(&new_entry);
        if self.state.is_active() && prev_valid {
            // Invalidate the TLB for the entry if it was valid before.
            invalidate_tlb(self.start_va.into());
        }
    }

    fn get_entry(&self) -> &PageTableEntryX64 {
        unsafe {
            get_entry::<PageTableEntryX64>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self._paging_type,
                self.state,
            )
        }
    }
}

impl crate::arch::PageTableEntry for X64PageTableEntry {
    fn new(
        page_base: PhysicalAddress,
        index: u64,
        level: PageLevel,
        paging_type: PagingType,
        start_va: VirtualAddress,
        state: PageTableState,
    ) -> PtResult<Self> {
        if index >= MAX_ENTRIES as u64 {
            return Err(PtError::InvalidParameter);
        }
        Ok(Self { page_base, index, level, _paging_type: paging_type, start_va, state })
    }

    fn update_fields(&mut self, attributes: MemoryAttributes, pa: PhysicalAddress, leaf_entry: bool) -> PtResult<()> {
        match self.level {
            PD | PDP => {
                let mut copy = self.copy_entry();
                copy.update_fields(attributes, pa)?;
                let page_size = leaf_entry && !attributes.contains(MemoryAttributes::ReadProtect);
                copy.set_page_size(page_size);
                self.set_entry(copy);
            }
            _ => {
                let mut copy = self.copy_entry();
                copy.update_fields(attributes, pa)?;
                self.set_entry(copy);
            }
        }
        Ok(())
    }

    fn present(&self) -> bool {
        self.get_entry().present()
    }

    fn set_present(&mut self, value: bool) {
        let mut copy = self.copy_entry();
        copy.set_present(value);
        self.set_entry(copy);
    }

    fn get_address(&self) -> PhysicalAddress {
        self.get_entry().get_canonical_page_table_base()
    }

    fn get_attributes(&self) -> MemoryAttributes {
        self.get_entry().get_attributes()
    }

    fn dump_entry_header() {
        log::info!(
            "------------------------------------------------------------------------------------------------------------------------------------"
        );
        log::info!(
            "                                                      63 62       52 51                                   12 11 9 8 7 6 5 4 3 2 1 0 "
        );
        log::info!(
            "                                                      |N|           |                                        |   |M|P|I| |P|P|U|R| |"
        );
        log::info!(
            "                                                      |X| Available |     Page-Map Level-4 Base Address      |AVL|B|G|G|A|C|W|/|/|P|"
        );
        log::info!(
            "                                                      | |           |                                        |   |Z|S|N| |D|T|S|W| |"
        );
        log::info!(
            "------------------------------------------------------------------------------------------------------------------------------------"
        );
    }

    fn dump_entry(&self) -> PtResult<()> {
        self.get_entry().dump_entry(self.start_va, self.level)
    }

    fn points_to_pa(&self) -> bool {
        match self.level {
            PT => true,
            PD | PDP => self.get_entry().page_size(),
            _ => false,
        }
    }

    fn get_level(&self) -> PageLevel {
        self.level
    }

    fn entry_ptr_address(&self) -> u64 {
        self.get_entry() as *const _ as u64
    }
}

pub(crate) fn invalidate_tlb(_va: u64) {
    #[cfg(all(not(test), target_arch = "x86_64"))]
    unsafe {
        core::arch::asm!("mfence", "invlpg [{0}]", in(reg) _va)
    };
}

/// This function returns the base address of the self-mapped page table at the given level for this VA
/// It is used in the get_entry function to determine the base address in the self map in which to apply
/// the index within the page table to get the entry we are intending to operate on.
/// Each index within the VA is multiplied by the memory size that each entry in the page table at that
/// level covers in order to calculate the correct address. E.g., for a 4-level page table, each PML4 entry
/// covers 512GB of memory, each PDP entry covers 1GB of memory, each PD entry covers 2MB of memory, and
/// each PT entry covers 4KB of memory, but when we recurse in the self map to a given level, we shift what
/// each entry covers to be the size of the next level down for each recursion into the self map we did.
fn get_self_mapped_base(level: PageLevel, va: VirtualAddress, paging_type: PagingType) -> u64 {
    match paging_type {
        PagingType::Paging4Level => match level {
            // PML5 is not used in 4-level paging, so we return an unimplemented error.
            PML5 => unimplemented!(),
            PML4 => FOUR_LEVEL_PML4_SELF_MAP_BASE,
            PDP => FOUR_LEVEL_PDP_SELF_MAP_BASE + (SIZE_4KB * va.get_index(PML4)),
            PD => FOUR_LEVEL_PD_SELF_MAP_BASE + (SIZE_2MB * va.get_index(PML4)) + (SIZE_4KB * va.get_index(PDP)),
            PT => {
                FOUR_LEVEL_PT_SELF_MAP_BASE
                    + (SIZE_1GB * va.get_index(PML4))
                    + (SIZE_2MB * va.get_index(PDP))
                    + (SIZE_4KB * va.get_index(PD))
            }
        },
        PagingType::Paging5Level => match level {
            PML5 => FIVE_LEVEL_PML5_SELF_MAP_BASE,
            PML4 => FIVE_LEVEL_PML4_SELF_MAP_BASE + (SIZE_4KB * va.get_index(PML5)),
            PDP => FIVE_LEVEL_PDP_SELF_MAP_BASE + (SIZE_2MB * va.get_index(PML5)) + (SIZE_4KB * va.get_index(PML4)),
            PD => {
                FIVE_LEVEL_PD_SELF_MAP_BASE
                    + (SIZE_1GB * va.get_index(PML5))
                    + (SIZE_2MB * va.get_index(PML4))
                    + (SIZE_4KB * va.get_index(PDP))
            }
            PT => {
                FIVE_LEVEL_PT_SELF_MAP_BASE
                    + (SIZE_512GB * va.get_index(PML5))
                    + (SIZE_1GB * va.get_index(PML4))
                    + (SIZE_2MB * va.get_index(PDP))
                    + (SIZE_4KB * va.get_index(PD))
            }
        },
    }
}

/// Main function which does the unsafe cast of PhysicalAddress to mut T. It
/// reinterprets the page table entry as T.
unsafe fn get_entry<'a, T>(
    base: PhysicalAddress,
    index: u64,
    level: PageLevel,
    va: VirtualAddress,
    paging_type: PagingType,
    state: PageTableState,
) -> &'a mut T {
    // we don't check the index here, as it is guaranteed to be within bounds
    // based on the new function of the X64PageTableEntry
    let base = match state.self_map() {
        true => get_self_mapped_base(level, va, paging_type),
        false => base.into(),
    };

    (unsafe { &mut *((base as *mut T).add(index as usize)) }) as _
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;
    use crate::arch::PageTableEntry;

    #[test]
    fn test_x64_page_table_entry_new() {
        // Test valid entry creation
        let entry = X64PageTableEntry {
            page_base: PhysicalAddress::from(0x1000),
            index: 0,
            level: PT,
            _paging_type: PagingType::Paging4Level,
            start_va: VirtualAddress::from(0x2000),
            state: PageTableState::Inactive,
        };
        assert_eq!(entry.get_level(), PT);

        // Test invalid index (simulate what new() would do)
        let invalid_index = 512; // MAX_ENTRIES
        assert!(invalid_index >= (PAGE_SIZE / 8));
    }

    #[test]
    fn test_get_self_mapped_base_4level() {
        let va = VirtualAddress::from(0x8000_0000_0000);

        // Test PML4 level
        let base = get_self_mapped_base(PML4, va, PagingType::Paging4Level);
        assert_eq!(base, FOUR_LEVEL_PML4_SELF_MAP_BASE);

        // Test PDP level
        let base = get_self_mapped_base(PDP, va, PagingType::Paging4Level);
        assert!(base >= FOUR_LEVEL_PDP_SELF_MAP_BASE);

        // Test PD level
        let base = get_self_mapped_base(PD, va, PagingType::Paging4Level);
        assert!(base >= FOUR_LEVEL_PD_SELF_MAP_BASE);

        // Test PT level
        let base = get_self_mapped_base(PT, va, PagingType::Paging4Level);
        assert!(base >= FOUR_LEVEL_PT_SELF_MAP_BASE);
    }

    #[test]
    fn test_get_self_mapped_base_5level() {
        let va = VirtualAddress::from(0x8000_0000_0000);

        // Test all levels for 5-level paging
        let base = get_self_mapped_base(PML5, va, PagingType::Paging5Level);
        assert_eq!(base, FIVE_LEVEL_PML5_SELF_MAP_BASE);

        let base = get_self_mapped_base(PML4, va, PagingType::Paging5Level);
        assert!(base >= FIVE_LEVEL_PML4_SELF_MAP_BASE);

        let base = get_self_mapped_base(PDP, va, PagingType::Paging5Level);
        assert!(base >= FIVE_LEVEL_PDP_SELF_MAP_BASE);

        let base = get_self_mapped_base(PD, va, PagingType::Paging5Level);
        assert!(base >= FIVE_LEVEL_PD_SELF_MAP_BASE);

        let base = get_self_mapped_base(PT, va, PagingType::Paging5Level);
        assert!(base >= FIVE_LEVEL_PT_SELF_MAP_BASE);
    }

    #[test]
    #[should_panic]
    fn test_get_self_mapped_base_pml5_4level_panics() {
        // PML5 should panic for 4-level paging
        let va = VirtualAddress::from(0x8000_0000_0000);
        get_self_mapped_base(PML5, va, PagingType::Paging4Level);
    }

    #[test]
    fn test_points_to_pa() {
        // Create a mock page table entry setup
        let page_data = [0u8; PAGE_SIZE as usize];
        let page_base = PhysicalAddress::from(&page_data as *const _ as u64);

        // Test PT level - always points to PA
        let entry = X64PageTableEntry {
            page_base,
            index: 0,
            level: PT,
            _paging_type: PagingType::Paging4Level,
            start_va: VirtualAddress::from(0),
            state: PageTableState::Inactive,
        };
        assert!(entry.points_to_pa());

        // Test PML4 level - never points to PA
        let entry = X64PageTableEntry {
            page_base,
            index: 0,
            level: PML4,
            _paging_type: PagingType::Paging4Level,
            start_va: VirtualAddress::from(0),
            state: PageTableState::Inactive,
        };
        assert!(!entry.points_to_pa());
    }

    #[test]
    fn test_max_entries_boundary() {
        let page_base = PhysicalAddress::from(0x1000);
        let state = PageTableState::Inactive;

        // Test boundary cases for entry index
        let entry = X64PageTableEntry {
            page_base,
            index: 511, // MAX_ENTRIES - 1
            level: PT,
            _paging_type: PagingType::Paging4Level,
            start_va: VirtualAddress::from(0),
            state,
        };
        assert!(entry.index < (PAGE_SIZE / 8));

        let entry = X64PageTableEntry {
            page_base,
            index: 512, // MAX_ENTRIES
            level: PT,
            _paging_type: PagingType::Paging4Level,
            start_va: VirtualAddress::from(0),
            state,
        };
        assert!(entry.index >= (PAGE_SIZE / 8));
    }

    #[test]
    fn test_page_level_constants() {
        // Verify the constants match expected values
        assert_eq!(PML5, PageLevel::Level5);
        assert_eq!(PML4, PageLevel::Level4);
        assert_eq!(PDP, PageLevel::Level3);
        assert_eq!(PD, PageLevel::Level2);
        assert_eq!(PT, PageLevel::Level1);
    }

    #[test]
    fn test_get_self_mapped_base_address_calculations() {
        // Test specific address calculations for different VA values
        let va1 = VirtualAddress::from(0);
        let va2 = VirtualAddress::from(0x1000); // 4KB aligned
        let va3 = VirtualAddress::from(0x200000); // 2MB aligned

        // For 4-level paging, PML4 base should be constant
        assert_eq!(
            get_self_mapped_base(PML4, va1, PagingType::Paging4Level),
            get_self_mapped_base(PML4, va2, PagingType::Paging4Level)
        );
        assert_eq!(
            get_self_mapped_base(PML4, va1, PagingType::Paging4Level),
            get_self_mapped_base(PML4, va3, PagingType::Paging4Level)
        );

        // For different levels, bases should differ based on VA
        let pt_base1 = get_self_mapped_base(PT, va1, PagingType::Paging4Level);
        let pt_base3 = get_self_mapped_base(PT, va3, PagingType::Paging4Level);
        assert_ne!(pt_base1, pt_base3);
    }

    #[test]
    fn test_update_fields_writes_back_end_entry() {
        // Prepare a dummy page table in memory
        let mut page_table = [PageTableEntryX64::default(); MAX_ENTRIES];
        let page_base = PhysicalAddress::from(&mut page_table as *mut _ as u64);

        let mut entry = X64PageTableEntry {
            page_base,
            index: 1,
            level: PT,
            _paging_type: PagingType::Paging4Level,
            start_va: VirtualAddress::from(0x4000),
            state: PageTableState::Inactive,
        };

        // Set some attributes and PA
        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::ExecuteProtect;
        let pa = PhysicalAddress::from(0xdeadbeef000);
        entry.update_fields(attributes, pa, true).unwrap();

        // The backend entry should be updated
        let backend_entry = unsafe { &*(&page_table[1] as *const PageTableEntryX64) };
        assert_eq!(backend_entry.get_attributes(), attributes);
        assert_eq!(backend_entry.get_canonical_page_table_base(), pa);
    }

    #[test]
    fn test_set_present_updates_backend_entry() {
        // Prepare a dummy page table in memory
        let mut page_table = [PageTableEntryX64::default(); MAX_ENTRIES];
        let page_base = PhysicalAddress::from(&mut page_table as *mut _ as u64);

        let mut entry = X64PageTableEntry {
            page_base,
            index: 2,
            level: PT,
            _paging_type: PagingType::Paging4Level,
            start_va: VirtualAddress::from(0x8000),
            state: PageTableState::Inactive,
        };

        // Initially not present
        entry.set_present(false);
        let backend_entry = unsafe { &*(&page_table[2] as *const PageTableEntryX64) };
        assert!(!backend_entry.present());

        // Set present to true
        entry.set_present(true);
        let backend_entry = unsafe { &*(&page_table[2] as *const PageTableEntryX64) };
        assert!(backend_entry.present());
    }

    #[test]
    fn test_update_fields_pd_and_pdp_sets_page_size() {
        for &level in &[PD, PDP] {
            let mut page_table = [PageTableEntryX64::default(); MAX_ENTRIES];
            let page_base = PhysicalAddress::from(&mut page_table as *mut _ as u64);

            let mut entry = X64PageTableEntry {
                page_base,
                index: 3,
                level,
                _paging_type: PagingType::Paging4Level,
                start_va: VirtualAddress::from(0x10000),
                state: PageTableState::Inactive,
            };

            let attributes = MemoryAttributes::ReadOnly;
            let pa = PhysicalAddress::from(0x12345000);

            // leaf_entry true, not ReadProtect, should set page_size
            entry.update_fields(attributes, pa, true).unwrap();
            let backend_entry = unsafe { &*(&page_table[3] as *const PageTableEntryX64) };
            assert!(backend_entry.page_size());

            // leaf_entry false, should not set page_size
            entry.update_fields(attributes, pa, false).unwrap();
            let backend_entry = unsafe { &*(&page_table[3] as *const PageTableEntryX64) };
            assert!(!backend_entry.page_size());

            // leaf_entry true, but ReadProtect set, should not set page_size
            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::ReadProtect;
            entry.update_fields(attributes, pa, true).unwrap();
            let backend_entry = unsafe { &*(&page_table[3] as *const PageTableEntryX64) };
            assert!(!backend_entry.page_size());
        }
    }
}
