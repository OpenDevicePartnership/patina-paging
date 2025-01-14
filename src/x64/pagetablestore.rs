use super::structs::{PageLevel, PageTableEntry, PhysicalAddress, VirtualAddress, PAGE_SIZE};
use crate::{MemoryAttributes, PagingType, PtResult};
use alloc::string::String;

/// Contains enough metadata to work with a single page table
pub struct X64PageTableStore {
    /// Physical page table base address
    base: PhysicalAddress,

    /// paging type is required to distinguish between PageTableEntry2MB vs
    /// PageTableEntry4KB entries at the lowest page level. For example, For
    /// Paging4KB4Level paging, at the lowest level(at Pt level), we use
    /// PageTableEntry4KB entries, but for Paging2MB4Level paging(in future),
    /// at the lowest level(at Pd level), we have to use PageTableEntry2MB
    /// entries.
    paging_type: PagingType,

    /// page table's page level(Pml5/Pml4/Pdp/Pd/Pt)
    level: PageLevel,

    /// start of the virtual address manageable by this page table
    start_va: VirtualAddress,

    /// end of the virtual address manageable by this page table
    end_va: VirtualAddress,
}

impl X64PageTableStore {
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

/// Iterator for X64PageTableStore to facilitate iterating over entries of a
/// page table
pub struct X64PageTableStoreIter {
    level: PageLevel,
    start_index: u64,
    end_index: u64,
    base: PhysicalAddress,
    paging_type: PagingType,
}

impl Iterator for X64PageTableStoreIter {
    type Item = X64PageTableEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start_index <= self.end_index {
            let index = self.start_index;
            self.start_index += 1;
            Some(X64PageTableEntry { page_base: self.base, index, level: self.level, _paging_type: self.paging_type })
        } else {
            None
        }
    }
}

impl IntoIterator for X64PageTableStore {
    type Item = X64PageTableEntry;

    type IntoIter = X64PageTableStoreIter;

    fn into_iter(self) -> Self::IntoIter {
        X64PageTableStoreIter {
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
pub struct X64PageTableEntry {
    page_base: PhysicalAddress,
    index: u64,
    level: PageLevel,
    _paging_type: PagingType,
}

impl X64PageTableEntry {
    pub fn update_fields(
        &mut self,
        attributes: MemoryAttributes,
        pa: PhysicalAddress,
        leaf_entry: bool,
    ) -> PtResult<()> {
        match self.level {
            PageLevel::Pa => panic!("unexpected call to update fields for pa paging level"),
            PageLevel::Pd | PageLevel::Pdp => {
                let entry = unsafe { get_entry::<PageTableEntry>(self.page_base, self.index) };
                let mut copy = entry.clone();
                copy.update_fields(attributes, pa)?;
                let page_size = leaf_entry && !attributes.contains(MemoryAttributes::ReadProtect);
                copy.set_page_size(page_size);
                entry.swap(&copy);
            }
            _ => {
                let entry = unsafe { get_entry::<PageTableEntry>(self.page_base, self.index) };
                let mut copy = entry.clone();
                copy.update_fields(attributes, pa)?;
                entry.swap(&copy);
            }
        }
        Ok(())
    }

    pub fn present(&self) -> bool {
        match self.level {
            PageLevel::Pa => panic!("unexpected call to get present bit for pa paging level"),
            _ => {
                let entry = unsafe { get_entry::<PageTableEntry>(self.page_base, self.index) };
                entry.present()
            }
        }
    }

    pub fn set_present(&self, value: bool) {
        match self.level {
            PageLevel::Pa => panic!("unexpected call to set present bit for pa paging level"),
            _ => {
                let entry = unsafe { get_entry::<PageTableEntry>(self.page_base, self.index) };
                let mut copy = entry.clone();
                copy.set_present(value);
                entry.swap(&copy);
            }
        }
    }

    pub fn get_canonical_page_table_base(&self) -> PhysicalAddress {
        match self.level {
            PageLevel::Pa => panic!("unexpected call to get canonical page table base for pa"),
            _ => {
                let entry = unsafe { get_entry::<PageTableEntry>(self.page_base, self.index) };
                entry.get_canonical_page_table_base()
            }
        }
    }

    pub fn get_attributes(&self) -> MemoryAttributes {
        match self.level {
            PageLevel::Pa => panic!("unexpected call to get attributes for pa paging level"),
            _ => {
                let entry = unsafe { get_entry::<PageTableEntry>(self.page_base, self.index) };
                entry.get_attributes()
            }
        }
    }

    pub fn dump_entry(&self) -> String {
        match self.level {
            PageLevel::Pa => panic!("unexpected call to get attributes for pa paging level"),
            _ => {
                let entry = unsafe { get_entry::<PageTableEntry>(self.page_base, self.index) };
                entry.dump_entry()
            }
        }
    }

    pub fn points_to_pa(&self) -> bool {
        match self.level {
            PageLevel::Pt => true,
            PageLevel::Pd | PageLevel::Pdp => {
                let entry = unsafe { get_entry::<PageTableEntry>(self.page_base, self.index) };
                entry.page_size()
            }
            _ => false,
        }
    }

    pub fn get_level(&self) -> PageLevel {
        self.level
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
