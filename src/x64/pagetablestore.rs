use super::structs::*;
use crate::structs::*;
use crate::{MemoryAttributes, PagingType, PtResult};
use alloc::string::String;

// Constants for page levels to conform to x64 standards.
const PML5: PageLevel = PageLevel::Level5;
const PML4: PageLevel = PageLevel::Level4;
const PDP: PageLevel = PageLevel::Level3;
const PD: PageLevel = PageLevel::Level2;
const PT: PageLevel = PageLevel::Level1;

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
    paging_type: PagingType,
    start_va: VirtualAddress,
    installed_and_self_mapped: bool,
}

impl crate::arch::PageTableEntry for X64PageTableEntry {
    fn new(
        page_base: PhysicalAddress,
        index: u64,
        level: PageLevel,
        paging_type: PagingType,
        start_va: VirtualAddress,
        installed_and_self_mapped: bool,
    ) -> Self {
        Self { page_base, index, level, paging_type, start_va, installed_and_self_mapped }
    }

    fn update_fields(&mut self, attributes: MemoryAttributes, pa: PhysicalAddress, leaf_entry: bool) -> PtResult<()> {
        match self.level {
            PD | PDP => {
                let entry = unsafe {
                    get_entry::<PageTableEntry>(
                        self.page_base,
                        self.index,
                        self.level,
                        self.start_va,
                        self.paging_type,
                        self.installed_and_self_mapped,
                    )
                };
                let mut copy = *entry;
                copy.update_fields(attributes, pa)?;
                let page_size = leaf_entry && !attributes.contains(MemoryAttributes::ReadProtect);
                copy.set_page_size(page_size);
                entry.swap(&copy);
            }
            _ => {
                let entry = unsafe {
                    get_entry::<PageTableEntry>(
                        self.page_base,
                        self.index,
                        self.level,
                        self.start_va,
                        self.paging_type,
                        self.installed_and_self_mapped,
                    )
                };
                let mut copy = *entry;
                copy.update_fields(attributes, pa)?;
                entry.swap(&copy);
            }
        }
        Ok(())
    }

    fn present(&self) -> bool {
        let entry = unsafe {
            get_entry::<PageTableEntry>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self.paging_type,
                self.installed_and_self_mapped,
            )
        };
        entry.present()
    }

    fn set_present(&mut self, value: bool) {
        let entry = unsafe {
            get_entry::<PageTableEntry>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self.paging_type,
                self.installed_and_self_mapped,
            )
        };
        let mut copy = *entry;
        copy.set_present(value);
        entry.swap(&copy);
    }

    fn get_canonical_page_table_base(&self) -> PhysicalAddress {
        let entry = unsafe {
            get_entry::<PageTableEntry>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self.paging_type,
                self.installed_and_self_mapped,
            )
        };
        entry.get_canonical_page_table_base()
    }

    fn get_attributes(&self) -> MemoryAttributes {
        let entry = unsafe {
            get_entry::<PageTableEntry>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self.paging_type,
                self.installed_and_self_mapped,
            )
        };
        entry.get_attributes()
    }

    fn dump_entry(&self) -> String {
        let entry = unsafe {
            get_entry::<PageTableEntry>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self.paging_type,
                self.installed_and_self_mapped,
            )
        };
        entry.dump_entry()
    }

    fn points_to_pa(&self) -> bool {
        match self.level {
            // PT always points to a PA
            PT => true,
            // PD and PDP can be large pages.
            PD | PDP => {
                let entry = unsafe {
                    get_entry::<PageTableEntry>(
                        self.page_base,
                        self.index,
                        self.level,
                        self.start_va,
                        self.paging_type,
                        self.installed_and_self_mapped,
                    )
                };
                entry.page_size()
            }
            _ => false,
        }
    }

    fn get_level(&self) -> PageLevel {
        self.level
    }

    fn raw_address(&self) -> u64 {
        let entry = unsafe {
            get_entry::<PageTableEntry>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self.paging_type,
                self.installed_and_self_mapped,
            )
        };
        entry as *mut _ as u64
    }

    fn supports_pa_entry(&self) -> bool {
        todo!()
    }
}

const MAX_ENTRIES: usize = (PAGE_SIZE / 8) as usize; // 512 entries

pub(crate) fn invalidate_self_map_va(_self_map_va: u64) {
    #[cfg(not(test))]
    unsafe {
        core::arch::asm!("mfence", "invlpg [{0}]", in(reg) _self_map_va)
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
        _ => panic!("unexpected paging type"),
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
    installed_and_self_mapped: bool,
) -> &'a mut T {
    if index >= MAX_ENTRIES as u64 {
        panic!("index {} cannot be greater than {}", index, MAX_ENTRIES - 1);
    }

    let base = match installed_and_self_mapped {
        true => get_self_mapped_base(level, va, paging_type),
        false => base.into(),
    };

    (unsafe { &mut *((base as *mut T).add(index as usize)) }) as _
}
