use super::structs::*;
use crate::paging::PageTableState;
use crate::structs::*;
use crate::{MemoryAttributes, PagingType, PtResult};

// Constants for page levels to conform to x64 standards.
pub const PML5: PageLevel = PageLevel::Level5;
pub const PML4: PageLevel = PageLevel::Level4;
pub const PDP: PageLevel = PageLevel::Level3;
pub const PD: PageLevel = PageLevel::Level2;
pub const PT: PageLevel = PageLevel::Level1;

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
    ) -> Self {
        Self { page_base, index, level, _paging_type: paging_type, start_va, state }
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

    fn dump_entry(&self) {
        self.get_entry().dump_entry(self.start_va, self.level);
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

const MAX_ENTRIES: usize = (PAGE_SIZE / 8) as usize; // 512 entries

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
            PML4 => FOUR_LEVEL_PML4_SELF_MAP_BASE,
            PDP => FOUR_LEVEL_PDP_SELF_MAP_BASE + (SIZE_4KB * va.get_index(PML4)),
            PD => FOUR_LEVEL_PD_SELF_MAP_BASE + (SIZE_2MB * va.get_index(PML4)) + (SIZE_4KB * va.get_index(PDP)),
            PT => {
                FOUR_LEVEL_PT_SELF_MAP_BASE
                    + (SIZE_1GB * va.get_index(PML4))
                    + (SIZE_2MB * va.get_index(PDP))
                    + (SIZE_4KB * va.get_index(PD))
            }
            _ => panic!("unexpected page level"),
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
    if index >= MAX_ENTRIES as u64 {
        panic!("index {} cannot be greater than {}", index, MAX_ENTRIES - 1);
    }

    let base = match state.self_map() {
        true => get_self_mapped_base(level, va, paging_type),
        false => base.into(),
    };

    (unsafe { &mut *((base as *mut T).add(index as usize)) }) as _
}
