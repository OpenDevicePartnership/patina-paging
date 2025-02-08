use mu_pi::fw_fs::ffs::attributes;

use crate::aarch64::structs::{AArch64Descriptor, PageLevel, VirtualAddress, PAGE_SIZE};
use crate::page_allocator::PageAllocator;
use crate::{MemoryAttributes, PagingType};
use crate::{PtError, PtResult};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
use std::rc::Rc;

// This struct will create a the buffer/memory needed for building the page
// tables
#[derive(Clone)]
pub struct TestPageAllocator {
    ref_impl: Rc<RefCell<TestPageAllocatorImpl>>,
    paging_type: PagingType,

    highest_page_level: PageLevel,
    lowest_page_level: PageLevel,
}

impl TestPageAllocator {
    pub fn new(num_pages: u64, paging_type: PagingType) -> Self {
        // For the given paging type identify the highest and lowest page levels.
        // This is used during page building to stop the recursion.
        let (highest_page_level, lowest_page_level) = match paging_type {
            PagingType::AArch64PageTable4KB => (PageLevel::Lvl0, PageLevel::Lvl3),
            _ => panic!("Paging type not supported"),
        };

        Self {
            ref_impl: Rc::new(RefCell::new(TestPageAllocatorImpl::new(num_pages))),
            paging_type,
            highest_page_level,
            lowest_page_level,
        }
    }

    pub fn pages_allocated(&self) -> u64 {
        self.ref_impl.borrow().page_index
    }

    // This method is called after building the page tables. It validates the
    // PageAllocator's memory against the expected entries. Specifically, each
    // page table entry's base address is checked against the expected base
    // address in the PageAllocator's memory. This is done by performing a
    // recursive page-walking logic similar to what was used during the actual
    // page-building process.

    //
    //        '     '
    // Page 4 ├─────┤◄──────────────────────┐
    //        │     │                       │
    //        │     │                       │
    //        │     │                       └───────────────────────────────────────┐
    //        │     │                         ┌─────┐                               │
    //        │     │                         │     │                               │
    //        │     │                         ├─────┤                               │
    //        │     │                         │     │                               │
    // Page 3 ├─────┤◄──────────────────────┐ ├─────┤                               │
    //        │     │                       │ │PML4E│                               │
    //        │     │                       │ ├─────┤                               │
    //        │     │                       │ │PML4E|                               │
    //        │     │                       │ └─────┘                               │
    //        │     │                       └─────────────────────────┐             │
    //        │     │                         ┌─────┐       ┌─────┐   │   ┌─────┐   │   ┌─────┐
    //        │     │                         │PML4E│       │     │   │   │     │   │   │     │
    // Page 2 ├─────┤◄──────────────────────┐ ├─────┤       ├─────┤   │   ├─────┤   │   ├─────┤
    //        │     │                       │ │PML4E│       │     │   │   │     │   │   │     │
    //        │     │                       │ ├─────┤       ├─────┤   │   ├─────┤   │   ├─────┤
    //        │     │                       │ │PML4E│       │PDPE │   │   |     │   │   │PTE  │
    //        │     │                       │ ├─────┤       ├─────┤   │   ├─────┤   │   ├─────┤
    //        │     │                       │ │PML4E|       │PDPE |   │   │PDE  |   │   │PTE  |
    //        │     │                       │ └─────┘       └─────┘   │   └─────┘   │   └─────┘
    //        │     │     ┌───────────────┐ └───────────┐             │             │
    // Page 1 ├─────┤◄────┘     ┌─────┐   │   ┌─────┐   │   ┌─────┐   │   ┌─────┐   │   ┌─────┐
    //        │     │           │     │   │   │PML4E|   │   │PDPE |   │   │PDE  |   │   │PTE  |
    //        │     │           ├─────┤   │   ├─────┤   │   ├─────┤   │   ├─────┤   │   ├─────┤
    //        │     │           │PML5E│   │   │PML4E│   │   │PDPE │   │   │PDE  │   │   │     │
    //        │     │           ├─────┤   │   ├─────┤   │   ├─────┤   │   ├─────┤   │   ├─────┤
    //        │     │           │PML5E│   │   │     │   │   │PDPE │   │   │     │   │   │     │
    //        │     │           ├─────┤   │   ├─────┤   │   ├─────┤   │   ├─────┤   │   ├─────┤
    //        │     │           │     │   │   │     │   │   │     │   │   │     │   │   │     │
    // Page 0 └─────┘◄──────────└─────┘   └───└─────┘   └───└─────┘   └───└─────┘   └───└─────┘
    //
    //  TestPageAllocator                         Page Tables
    //       Memory
    //
    pub fn validate_pages(&self, address: u64, size: u64, attributes: MemoryAttributes) {
        let address = VirtualAddress::new(address);
        let start_va = address;
        let end_va = address + size - 1;

        // page index keep track of the global page being used from the memory.
        // This needed for the recursive page walk logic
        let mut page_index = 0;

        self.validate_pages_internal(start_va, end_va, self.highest_page_level, &mut page_index, attributes);
    }

    fn validate_pages_internal(
        &self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        page_index: &mut u64,
        attributes: MemoryAttributes,
    ) {
        let start_index = start_va.get_index(level);
        let end_index = end_va.get_index(level);
        let page = self.get_page(*page_index).unwrap();
        let mut va = start_va;
        for index in start_index..=end_index {
            let leaf: bool;
            unsafe {
                // hex_dump(page.add(index as usize) as *const u8, 8);
                leaf = self.validate_page_entry(
                    page.add(index as usize),
                    va.into(),
                    self.get_memory_base().add((PAGE_SIZE as usize) * (*page_index as usize + 1)) as u64,
                    level,
                    attributes,
                );

                // We only consume further pages from PageAllocator memory
                // for page tables higher than PT type
                if !leaf {
                    *page_index += 1;
                }
            }

            let next_level_start_va = va;
            let curr_va_ceiling = va.round_up(level);
            let next_level_end_va = VirtualAddress::min(curr_va_ceiling, end_va);

            if !leaf {
                let next_level = level - 1;
                self.validate_pages_internal(
                    next_level_start_va,
                    next_level_end_va,
                    next_level,
                    page_index,
                    attributes,
                );
            }

            va = va.get_next_va(level);
        }
    }

    fn validate_page_entry(
        &self,
        entry_ptr: *const u64,
        virtual_address: u64,
        next_page_table_address: u64,
        level: PageLevel,
        expected_attributes: MemoryAttributes,
    ) -> bool {
        unsafe {
            let table_base = *entry_ptr;

            if self.paging_type != PagingType::AArch64PageTable4KB {
                panic!("Paging type not supported");
            }

            let pte = AArch64Descriptor::from_bits(table_base);
            assert!(pte.valid());
            let page_base: u64 = pte.get_canonical_page_table_base().into();
            let attributes = pte.get_attributes();
            let leaf = match level {
                PageLevel::Lvl3 => true,
                PageLevel::Lvl1 | PageLevel::Lvl2 => !pte.table_desc(),
                _ => false,
            };

            if leaf {
                assert_eq!(page_base, virtual_address);
                assert_eq!(attributes, expected_attributes);
            } else {
                assert_eq!(page_base, next_page_table_address);
                assert_eq!(attributes, MemoryAttributes::Writeback);
            }

            leaf
        }
    }

    fn get_memory_base(&self) -> *const u8 {
        self.ref_impl.borrow().get_memory_base()
    }

    fn get_page(&self, index: u64) -> PtResult<*const u64> {
        self.ref_impl.borrow().get_page(index)
    }
}

impl PageAllocator for TestPageAllocator {
    fn allocate_page(&mut self, align: u64, size: u64, _is_root: bool) -> PtResult<u64> {
        self.ref_impl.borrow_mut().allocate_page(align, size)
    }
}

struct TestPageAllocatorImpl {
    memory: (*mut u8, Layout),
    page_index: u64,
    max_pages: u64,
}

impl TestPageAllocatorImpl {
    fn new(num_pages: u64) -> Self {
        let layout = Layout::from_size_align((num_pages * PAGE_SIZE) as usize, PAGE_SIZE as usize).unwrap();
        let ptr = unsafe {
            let ptr = System.alloc(layout);
            if ptr.is_null() {
                panic!("Unable to allocate memory({} bytes) for {} pages(4K)", num_pages * PAGE_SIZE, num_pages);
            }
            // zero the buffer
            std::ptr::write_bytes(ptr, 0, layout.size());
            ptr
        };

        Self { memory: (ptr, layout), page_index: 0, max_pages: num_pages }
    }

    fn allocate_page(&mut self, _align: u64, _size: u64) -> PtResult<u64> {
        if self.page_index >= self.max_pages {
            return Err(PtError::OutOfResources);
        }

        let ptr = unsafe { self.memory.0.add((PAGE_SIZE * self.page_index) as usize) as u64 };
        self.page_index += 1;
        Ok(ptr)
    }

    fn get_page(&self, index: u64) -> PtResult<*const u64> {
        if index >= self.page_index {
            return Err(PtError::OutOfResources);
        }

        let ptr = unsafe { self.memory.0.add((PAGE_SIZE * index) as usize) as *const u64 };
        Ok(ptr)
    }

    fn get_memory_base(&self) -> *const u8 {
        self.memory.0
    }
}

impl Drop for TestPageAllocatorImpl {
    fn drop(&mut self) {
        unsafe {
            System.dealloc(self.memory.0, self.memory.1);
        };
    }
}
