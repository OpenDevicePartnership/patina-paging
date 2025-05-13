use super::{structs::*, SIZE_1GB, SIZE_2MB, SIZE_4KB, SIZE_512GB};
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

    /// Whether the page table is installed and self-mapped
    installed_and_self_mapped: bool,
}

impl X64PageTableStore {
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

/// Iterator for X64PageTableStore to facilitate iterating over entries of a
/// page table
pub struct X64PageTableStoreIter {
    level: PageLevel,
    start_index: u64,
    end_index: u64,
    base: PhysicalAddress,
    paging_type: PagingType,
    start_va: VirtualAddress,
    installed_and_self_mapped: bool,
}

impl Iterator for X64PageTableStoreIter {
    type Item = X64PageTableEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start_index <= self.end_index {
            let index = self.start_index;
            self.start_index += 1;
            Some(X64PageTableEntry::new(
                self.base,
                index,
                self.level,
                self.paging_type,
                self.start_va,
                self.installed_and_self_mapped,
            ))
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
#[derive(Debug)]
pub struct X64PageTableEntry {
    page_base: PhysicalAddress,
    index: u64,
    level: PageLevel,
    _paging_type: PagingType,
    start_va: VirtualAddress,
    installed_and_self_mapped: bool,
}

impl X64PageTableEntry {
    pub fn new(
        page_base: PhysicalAddress,
        index: u64,
        level: PageLevel,
        paging_type: PagingType,
        start_va: VirtualAddress,
        installed_and_self_mapped: bool,
    ) -> Self {
        Self { page_base, index, level, _paging_type: paging_type, start_va, installed_and_self_mapped }
    }

    pub fn update_fields(
        &mut self,
        attributes: MemoryAttributes,
        pa: PhysicalAddress,
        leaf_entry: bool,
    ) -> PtResult<()> {
        match self.level {
            PageLevel::Pd | PageLevel::Pdp => {
                let entry = unsafe {
                    get_entry::<PageTableEntry>(
                        self.page_base,
                        self.index,
                        self.level,
                        self.start_va,
                        self._paging_type,
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
                        self._paging_type,
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

    pub fn present(&self) -> bool {
        let entry = unsafe {
            get_entry::<PageTableEntry>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self._paging_type,
                self.installed_and_self_mapped,
            )
        };
        entry.present()
    }

    pub fn set_present(&self, value: bool) {
        let entry = unsafe {
            get_entry::<PageTableEntry>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self._paging_type,
                self.installed_and_self_mapped,
            )
        };
        let mut copy = *entry;
        copy.set_present(value);
        entry.swap(&copy);
    }

    pub fn get_canonical_page_table_base(&self) -> PhysicalAddress {
        let entry = unsafe {
            get_entry::<PageTableEntry>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self._paging_type,
                self.installed_and_self_mapped,
            )
        };
        entry.get_canonical_page_table_base()
    }

    pub fn get_attributes(&self) -> MemoryAttributes {
        let entry = unsafe {
            get_entry::<PageTableEntry>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self._paging_type,
                self.installed_and_self_mapped,
            )
        };
        entry.get_attributes()
    }

    pub fn dump_entry(&self) -> String {
        let entry = unsafe {
            get_entry::<PageTableEntry>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self._paging_type,
                self.installed_and_self_mapped,
            )
        };
        entry.dump_entry()
    }

    pub fn points_to_pa(&self) -> bool {
        match self.level {
            PageLevel::Pt => true,
            PageLevel::Pd | PageLevel::Pdp => {
                let entry = unsafe {
                    get_entry::<PageTableEntry>(
                        self.page_base,
                        self.index,
                        self.level,
                        self.start_va,
                        self._paging_type,
                        self.installed_and_self_mapped,
                    )
                };
                entry.page_size()
            }
            _ => false,
        }
    }

    pub fn get_level(&self) -> PageLevel {
        self.level
    }

    pub fn raw_address(&self) -> u64 {
        let entry = unsafe {
            get_entry::<PageTableEntry>(
                self.page_base,
                self.index,
                self.level,
                self.start_va,
                self._paging_type,
                self.installed_and_self_mapped,
            )
        };
        entry as *mut _ as u64
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
            PageLevel::Pml4 => FOUR_LEVEL_PML4_SELF_MAP_BASE,
            PageLevel::Pdp => FOUR_LEVEL_PDP_SELF_MAP_BASE + (SIZE_4KB * va.get_index(PageLevel::Pml4)),
            PageLevel::Pd => {
                FOUR_LEVEL_PD_SELF_MAP_BASE
                    + (SIZE_2MB * va.get_index(PageLevel::Pml4))
                    + (SIZE_4KB * va.get_index(PageLevel::Pdp))
            }
            PageLevel::Pt => {
                FOUR_LEVEL_PT_SELF_MAP_BASE
                    + (SIZE_1GB * va.get_index(PageLevel::Pml4))
                    + (SIZE_2MB * va.get_index(PageLevel::Pdp))
                    + (SIZE_4KB * va.get_index(PageLevel::Pd))
            }
            _ => panic!("unexpected page level"),
        },
        PagingType::Paging5Level => match level {
            PageLevel::Pml5 => FIVE_LEVEL_PML5_SELF_MAP_BASE,
            PageLevel::Pml4 => FIVE_LEVEL_PML4_SELF_MAP_BASE + (SIZE_4KB * va.get_index(PageLevel::Pml5)),
            PageLevel::Pdp => {
                FIVE_LEVEL_PDP_SELF_MAP_BASE
                    + (SIZE_2MB * va.get_index(PageLevel::Pml5))
                    + (SIZE_4KB * va.get_index(PageLevel::Pml4))
            }
            PageLevel::Pd => {
                FIVE_LEVEL_PD_SELF_MAP_BASE
                    + (SIZE_1GB * va.get_index(PageLevel::Pml5))
                    + (SIZE_2MB * va.get_index(PageLevel::Pml4))
                    + (SIZE_4KB * va.get_index(PageLevel::Pdp))
            }
            PageLevel::Pt => {
                FIVE_LEVEL_PT_SELF_MAP_BASE
                    + (SIZE_512GB * va.get_index(PageLevel::Pml5))
                    + (SIZE_1GB * va.get_index(PageLevel::Pml4))
                    + (SIZE_2MB * va.get_index(PageLevel::Pdp))
                    + (SIZE_4KB * va.get_index(PageLevel::Pd))
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
