#[cfg(all(not(test), target_arch = "aarch64"))]
use super::reg;
use super::structs::*;
use crate::{
    MemoryAttributes, PagingType, PtError, PtResult, arch::PageTableEntry, paging::PageTableState, structs::*,
};

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
pub struct AArch64PageTableEntry {
    page_base: PhysicalAddress,
    index: u64,
    level: PageLevel,
    _paging_type: PagingType,
    start_va: VirtualAddress,
    state: PageTableState,
}

impl AArch64PageTableEntry {
    fn get_entry(&self) -> &AArch64Descriptor {
        let entry = unsafe {
            get_entry::<AArch64Descriptor>(self.page_base, self.index, self.level, self.start_va, self.state)
        };

        entry
    }

    fn copy_entry(&self) -> AArch64Descriptor {
        *self.get_entry()
    }

    fn swap_entry(&mut self, new_entry: AArch64Descriptor) {
        if self.state.is_active() {
            #[cfg(all(not(test), target_arch = "aarch64"))]
            unsafe {
                reg::replace_live_xlat_entry(self.entry_ptr_address(), new_entry.get_u64(), self.start_va.into());
            }
        } else {
            let entry = unsafe {
                get_entry::<AArch64Descriptor>(self.page_base, self.index, self.level, self.start_va, self.state)
            };

            *entry = new_entry;
        }
    }
}

impl PageTableEntry for AArch64PageTableEntry {
    fn new(
        page_base: PhysicalAddress,
        index: u64,
        level: PageLevel,
        paging_type: PagingType,
        start_va: VirtualAddress,
        state: PageTableState,
    ) -> PtResult<Self> {
        if paging_type != PagingType::Paging4Level || index >= MAX_ENTRIES as u64 {
            return Err(PtError::InvalidParameter);
        }
        Ok(Self { page_base, index, level, _paging_type: paging_type, start_va, state })
    }

    fn update_fields(&mut self, attributes: MemoryAttributes, pa: PhysicalAddress, block: bool) -> PtResult<()> {
        let mut entry = self.copy_entry();
        entry.update_fields(attributes, pa)?;
        entry.set_table_desc(self.level == PageLevel::Level1 || !block);
        self.swap_entry(entry);
        Ok(())
    }

    fn present(&self) -> bool {
        self.get_entry().valid()
    }

    fn get_address(&self) -> PhysicalAddress {
        self.get_entry().get_canonical_page_table_base()
    }

    fn entry_ptr_address(&self) -> u64 {
        self.get_entry() as *const _ as u64
    }

    fn get_attributes(&self) -> MemoryAttributes {
        self.get_entry().get_attributes()
    }

    fn set_present(&mut self, value: bool) {
        let mut entry = self.copy_entry();
        entry.set_valid(value);
        self.swap_entry(entry);
    }

    fn points_to_pa(&self) -> bool {
        match self.level {
            PageLevel::Level1 => true,
            PageLevel::Level2 | PageLevel::Level3 => !self.get_entry().table_desc(),
            _ => false,
        }
    }

    fn get_level(&self) -> PageLevel {
        self.level
    }

    fn dump_entry_header() {
        log::info!(
            "----------------------------------------------------------------------------------------------------------------------------------"
        );
    }

    fn dump_entry(&self) -> PtResult<()> {
        self.get_entry().dump_entry(self.start_va, self.level)
    }
}

/// This function returns the base address of the self-mapped page table at the given level for this VA
/// It is used in the get_entry function to determine the base address in the self map in which to apply
/// the index within the page table to get the entry we are intending to operate on.
/// Each index within the VA is multiplied by the memory size that each entry in the page table at that
/// level covers in order to calculate the correct address. E.g., for a 4-level page table, each PML4 entry
/// covers 512GB of memory, each PDP entry covers 1GB of memory, each PD entry covers 2MB of memory, and
/// each PT entry covers 4KB of memory, but when we recurse in the self map to a given level, we shift what
/// each entry covers to be the size of the next level down for each recursion into the self map we did.
fn get_self_mapped_base(level: PageLevel, va: VirtualAddress) -> u64 {
    match level {
        // AArch64 does not support 5-level paging, so we return an unimplemented error.
        PageLevel::Level5 => unimplemented!(),
        PageLevel::Level4 => FOUR_LEVEL_4_SELF_MAP_BASE,
        PageLevel::Level3 => FOUR_LEVEL_3_SELF_MAP_BASE + (SIZE_4KB * va.get_index(PageLevel::Level4)),
        PageLevel::Level2 => {
            FOUR_LEVEL_2_SELF_MAP_BASE
                + (SIZE_2MB * va.get_index(PageLevel::Level4))
                + (SIZE_4KB * va.get_index(PageLevel::Level3))
        }
        PageLevel::Level1 => {
            FOUR_LEVEL_1_SELF_MAP_BASE
                + (SIZE_1GB * va.get_index(PageLevel::Level4))
                + (SIZE_2MB * va.get_index(PageLevel::Level3))
                + (SIZE_4KB * va.get_index(PageLevel::Level2))
        }
    }
}

/// Main function which does the unsafe cast of PhysicalAddress to mut T. It
/// reinterprets the page table entry as T.
unsafe fn get_entry<'a, T>(
    base: PhysicalAddress,
    index: u64,
    level: PageLevel,
    table_va: VirtualAddress,
    state: PageTableState,
) -> &'a mut T {
    // we don't check the index here, as it is guaranteed to be within bounds
    // based on the new function of the AArch64PageTableEntry
    let base = match state.self_map() {
        true => get_self_mapped_base(level, table_va),
        false => base.into(),
    };
    unsafe { &mut *((base as *mut T).add(index as usize)) }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryAttributes, PagingType, arch::PageTableEntry, paging::PageTableState};

    // Helper to create a backing page table
    fn make_backing_table() -> Box<[AArch64Descriptor; MAX_ENTRIES]> {
        Box::new([AArch64Descriptor::default(); MAX_ENTRIES])
    }

    // Helper to get a PhysicalAddress from a pointer
    fn ptr_to_pa<T>(ptr: *const T) -> PhysicalAddress {
        PhysicalAddress::from(ptr as u64)
    }

    #[test]
    fn test_entry_update_and_backing_check() {
        let table = make_backing_table();
        let table_pa = ptr_to_pa(table.as_ptr());

        let index = 10;
        let level = PageLevel::Level2;
        let va = VirtualAddress::from(0x4000_0000u64);
        let mut entry = AArch64PageTableEntry::new(
            table_pa,
            index as u64,
            level,
            PagingType::Paging4Level,
            va,
            PageTableState::Inactive,
        )
        .unwrap();

        // Update entry fields
        let attrs = MemoryAttributes::Writeback | MemoryAttributes::ReadOnly;
        let pa = PhysicalAddress::from(0x1234_0000u64);
        entry.update_fields(attrs, pa, false).unwrap();

        // Check that the backing entry was updated
        let backing_entry = &table[index];
        assert_eq!(backing_entry.get_canonical_page_table_base(), pa);
        assert_eq!(backing_entry.get_attributes(), attrs);
        assert!(backing_entry.valid());
    }

    #[test]
    fn test_set_present_and_backing_check() {
        let table = make_backing_table();
        let table_pa = ptr_to_pa(table.as_ptr());

        let index = 5;
        let level = PageLevel::Level3;
        let va = VirtualAddress::from(0x8000_0000u64);
        let mut entry = AArch64PageTableEntry::new(
            table_pa,
            index as u64,
            level,
            PagingType::Paging4Level,
            va,
            PageTableState::Inactive,
        )
        .unwrap();

        // Initially not present
        entry.set_present(false);
        assert!(!table[index].valid());

        // Set present
        entry.set_present(true);
        assert!(table[index].valid());
    }

    #[test]
    fn test_points_to_pa_logic() {
        let mut table = make_backing_table();
        let table_pa = ptr_to_pa(table.as_ptr());

        let va = VirtualAddress::from(0x1000_0000u64);

        // Level1 always points to PA
        let entry1 = AArch64PageTableEntry::new(
            table_pa,
            0,
            PageLevel::Level1,
            PagingType::Paging4Level,
            va,
            PageTableState::Inactive,
        )
        .unwrap();
        assert!(entry1.points_to_pa());

        // Level2 and Level3 depend on table_desc
        let entry2 = AArch64PageTableEntry::new(
            table_pa,
            1,
            PageLevel::Level2,
            PagingType::Paging4Level,
            va,
            PageTableState::Inactive,
        )
        .unwrap();
        // Set table_desc = false
        table[1].set_table_desc(false);
        assert!(entry2.points_to_pa());
        // Set table_desc = true
        table[1].set_table_desc(true);
        assert!(!entry2.points_to_pa());
    }

    #[test]
    fn test_entry_ptr_address_matches_backing() {
        let table = make_backing_table();
        let table_pa = ptr_to_pa(table.as_ptr());

        let index = 7;
        let va = VirtualAddress::from(0x2000_0000u64);
        let entry = AArch64PageTableEntry::new(
            table_pa,
            index as u64,
            PageLevel::Level3,
            PagingType::Paging4Level,
            va,
            PageTableState::Inactive,
        )
        .unwrap();

        let expected_addr = &table[index] as *const _ as u64;
        assert_eq!(entry.entry_ptr_address(), expected_addr);
    }
}
