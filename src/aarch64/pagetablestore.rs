use super::structs::{AArch64Descriptor, PageLevel, PhysicalAddress, VirtualAddress, PAGE_SIZE};
use crate::{MemoryAttributes, PagingType, PtResult};
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
}

impl AArch64PageTableStore {
    pub fn new(
        base: PhysicalAddress,
        level: PageLevel,
        paging_type: PagingType,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
    ) -> Self {
        Self { base, level, paging_type, start_va, end_va }
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
                _level: self.level,
                _paging_type: self.paging_type,
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
    _level: PageLevel,
    _paging_type: PagingType,
}

impl AArch64PageTableEntry {
    pub fn update_fields(&mut self, attributes: MemoryAttributes, pa: PhysicalAddress) -> PtResult<()> {
        let entry = unsafe { get_entry::<AArch64Descriptor>(self.page_base, self.index) };
        entry.update_fields(attributes, pa)
    }

    pub fn update_shadow_fields(&mut self, attributes: MemoryAttributes, pa: PhysicalAddress) -> u64 {
        let entry = unsafe { get_entry::<AArch64Descriptor>(self.page_base, self.index) };
        let mut shadow_entry = entry.clone();
        match shadow_entry.update_fields(attributes, pa) {
            Ok(_) => {}
            Err(_) => panic!("Failed to update shadow table entry"),
        }
        shadow_entry.get_u64()
    }

    pub fn is_valid(&self) -> bool {
        let entry = unsafe { get_entry::<AArch64Descriptor>(self.page_base, self.index) };
        entry.valid()
    }

    pub fn get_canonical_page_table_base(&self) -> PhysicalAddress {
        let entry = unsafe { get_entry::<AArch64Descriptor>(self.page_base, self.index) };
        entry.get_canonical_page_table_base()
    }

    pub fn raw_address(&self) -> u64 {
        let entry = unsafe { get_entry::<AArch64Descriptor>(self.page_base, self.index) };
        entry as *mut _ as u64
    }

    pub fn get_attributes(&self) -> MemoryAttributes {
        let entry = unsafe { get_entry::<AArch64Descriptor>(self.page_base, self.index) };
        entry.get_attributes()
    }

    pub fn set_invalid(&self) {
        let entry = unsafe { get_entry::<AArch64Descriptor>(self.page_base, self.index) };
        entry.set_valid(false);
    }

    pub fn dump_entry(&self) -> String {
        let entry = unsafe { get_entry::<AArch64Descriptor>(self.page_base, self.index) };
        entry.dump_entry()
    }
}

const MAX_ENTRIES: usize = (PAGE_SIZE / 8) as usize; // 512 entries

/// Main function which does the unsafe cast of PhysicalAddress to mut T. It
/// reinterprets the page table entry as T.
pub unsafe fn get_entry<'a, T>(base: PhysicalAddress, index: u64) -> &'a mut T {
    if index >= MAX_ENTRIES as u64 {
        panic!("index {} cannot be greater than {}", index, MAX_ENTRIES - 1);
    }

    let base: u64 = base.into();
    if base == 0 {
        panic!("Physical base address of a page table is not expected to be zero");
    }

    unsafe { &mut *((base as *mut T).add(index as usize)) }
}
