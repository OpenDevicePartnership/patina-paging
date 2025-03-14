use super::structs::*;
use crate::{MemoryAttributes, PagingType, PtResult, SIZE_1GB, SIZE_2MB, SIZE_4KB};
use alloc::string::String;

/// Contains enough metadata to work with a single page table
pub struct AArch64PageTableStore {
    /// Physical page table base address
    base: PhysicalAddress,

    /// paging type is required to distinguish between AArch64PageTable4KB vs.
    /// potentially, AArch64PageTable64KB entries at the lowest page level. For
    /// example, For Paging4KB4Level paging, at the lowest level(at Pt level),
    /// we use PageTableEntry4KB entries, but for Paging2MB4Level paging(in
    /// future), at the lowest level(at Pd level), we have to use
    /// PageTableEntry2MB entries.
    paging_type: PagingType,

    /// page table's page level(Lvl0/Lvl1/Lvl2/Lvl3)
    level: PageLevel,

    /// start of the virtual address manageable by this page table
    start_va: VirtualAddress,

    /// end of the virtual address manageable by this page table
    end_va: VirtualAddress,

    /// Whether the page table is installed and self-mapped
    installed_and_self_mapped: bool,
}

impl AArch64PageTableStore {
    pub fn new(
        base: PhysicalAddress,
        level: PageLevel,
        paging_type: PagingType,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        installed_and_self_mapped: bool,
    ) -> Self {
        Self { base, level, paging_type, start_va, end_va, installed_and_self_mapped }
    }
}

/// Iterator for AArch64PageTableStore to facilitate iterating over entries of a
/// page table
pub struct AArch64PageTableStoreIter {
    level: PageLevel,
    start_index: u64,
    end_index: u64,
    base: PhysicalAddress,
    paging_type: PagingType,
    start_va: VirtualAddress,
    installed_and_self_mapped: bool,
}

impl Iterator for AArch64PageTableStoreIter {
    type Item = AArch64PageTableEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start_index <= self.end_index {
            let index = self.start_index;
            self.start_index += 1;
            Some(AArch64PageTableEntry {
                page_base: self.base,
                index,
                level: self.level,
                _paging_type: self.paging_type,
                start_va: self.start_va,
                installed_and_self_mapped: self.installed_and_self_mapped,
            })
        } else {
            None
        }
    }
}

impl IntoIterator for AArch64PageTableStore {
    type Item = AArch64PageTableEntry;

    type IntoIter = AArch64PageTableStoreIter;

    fn into_iter(self) -> Self::IntoIter {
        AArch64PageTableStoreIter {
            level: self.level,
            start_index: self.start_va.get_index(self.level),
            end_index: self.end_va.get_index(self.level),
            base: self.base,
            paging_type: self.paging_type,
            start_va: self.start_va,
            installed_and_self_mapped: self.installed_and_self_mapped,
        }
    }
}

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
    installed_and_self_mapped: bool,
}

impl AArch64PageTableEntry {
    pub fn new(
        page_base: PhysicalAddress,
        index: u64,
        level: PageLevel,
        _paging_type: PagingType,
        start_va: VirtualAddress,
        installed_and_self_mapped: bool,
    ) -> Self {
        Self { page_base, index, level, _paging_type, start_va, installed_and_self_mapped }
    }

    pub fn update_fields(&mut self, attributes: MemoryAttributes, pa: PhysicalAddress, block: bool) -> PtResult<()> {
        let entry = unsafe {
            get_entry::<AArch64Descriptor>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self.installed_and_self_mapped,
            )
        };
        entry.update_fields(attributes, pa)?;
        entry.set_table_desc(self.level == PageLevel::Lvl3 || !block);
        Ok(())
    }

    pub fn update_shadow_fields(&mut self, attributes: MemoryAttributes, pa: PhysicalAddress, block: bool) -> u64 {
        let entry = unsafe {
            get_entry::<AArch64Descriptor>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self.installed_and_self_mapped,
            )
        };
        let mut shadow_entry = *entry;
        match shadow_entry.update_fields(attributes, pa) {
            Ok(_) => {}
            Err(_) => panic!("Failed to update shadow table entry"),
        }

        shadow_entry.set_table_desc(self.level == PageLevel::Lvl3 || !block);
        shadow_entry.get_u64()
    }

    pub fn is_valid(&self) -> bool {
        let entry = unsafe {
            get_entry::<AArch64Descriptor>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self.installed_and_self_mapped,
            )
        };
        entry.valid()
    }

    pub fn get_canonical_page_table_base(&self) -> PhysicalAddress {
        let entry = unsafe {
            get_entry::<AArch64Descriptor>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self.installed_and_self_mapped,
            )
        };
        entry.get_canonical_page_table_base()
    }

    pub fn raw_address(&self) -> u64 {
        let entry = unsafe {
            get_entry::<AArch64Descriptor>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self.installed_and_self_mapped,
            )
        };
        entry as *mut _ as u64
    }

    pub fn get_attributes(&self) -> MemoryAttributes {
        let entry = unsafe {
            get_entry::<AArch64Descriptor>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self.installed_and_self_mapped,
            )
        };
        entry.get_attributes()
    }

    pub fn set_invalid(&self) {
        let entry = unsafe {
            get_entry::<AArch64Descriptor>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self.installed_and_self_mapped,
            )
        };
        entry.set_valid(false);
    }

    pub fn dump_entry(&self) -> String {
        let entry = unsafe {
            get_entry::<AArch64Descriptor>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self.installed_and_self_mapped,
            )
        };
        entry.dump_entry()
    }

    pub fn is_block_entry(&self) -> bool {
        match self.level {
            PageLevel::Lvl3 => true,
            PageLevel::Lvl1 | PageLevel::Lvl2 => {
                let entry = unsafe {
                    get_entry::<AArch64Descriptor>(
                        self.page_base,
                        self.index,
                        self.level,
                        self.start_va,
                        self.installed_and_self_mapped,
                    )
                };
                !entry.table_desc()
            }
            _ => false,
        }
    }

    pub fn get_level(&self) -> PageLevel {
        self.level
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
        PageLevel::Lvl0 => FOUR_LEVEL_PML4_SELF_MAP_BASE,
        PageLevel::Lvl1 => FOUR_LEVEL_PDP_SELF_MAP_BASE + (SIZE_4KB * va.get_index(PageLevel::Lvl0)),
        PageLevel::Lvl2 => {
            FOUR_LEVEL_PD_SELF_MAP_BASE
                + (SIZE_2MB * va.get_index(PageLevel::Lvl0))
                + (SIZE_4KB * va.get_index(PageLevel::Lvl1))
        }
        PageLevel::Lvl3 => {
            FOUR_LEVEL_PT_SELF_MAP_BASE
                + (SIZE_1GB * va.get_index(PageLevel::Lvl0))
                + (SIZE_2MB * va.get_index(PageLevel::Lvl1))
                + (SIZE_4KB * va.get_index(PageLevel::Lvl2))
        }
    }
}

/// Main function which does the unsafe cast of PhysicalAddress to mut T. It
/// reinterprets the page table entry as T.
unsafe fn get_entry<'a, T>(
    base: PhysicalAddress,
    index: u64,
    level: PageLevel,
    va: VirtualAddress,
    installed_and_self_mapped: bool,
) -> &'a mut T {
    if index >= MAX_ENTRIES as u64 {
        panic!("index {} cannot be greater than {}", index, MAX_ENTRIES - 1);
    }

    let base = match installed_and_self_mapped {
        true => get_self_mapped_base(level, va),
        false => base.into(),
    };
    unsafe { &mut *((base as *mut T).add(index as usize)) }
}
