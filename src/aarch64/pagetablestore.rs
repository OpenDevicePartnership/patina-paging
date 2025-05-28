#[cfg(all(not(test), target_arch = "aarch64"))]
use super::reg;
use super::structs::*;
use crate::{MemoryAttributes, PagingType, PtResult, arch::PageTableEntry, paging::PageTableState, structs::*};

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
    ) -> Self {
        assert!(paging_type == PagingType::Paging4Level);
        Self { page_base, index, level, _paging_type: paging_type, start_va, state }
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

    fn dump_entry(&self) {
        self.get_entry().dump_entry(self.start_va, self.level);
    }
}

const MAX_ENTRIES: usize = (PAGE_SIZE / 8) as usize; // 512 entries

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
    if index >= MAX_ENTRIES as u64 {
        panic!("index {} cannot be greater than {}", index, MAX_ENTRIES - 1);
    }

    let base = match state.self_map() {
        true => get_self_mapped_base(level, table_va),
        false => base.into(),
    };
    unsafe { &mut *((base as *mut T).add(index as usize)) }
}
