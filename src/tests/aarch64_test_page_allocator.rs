use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
use std::rc::Rc;

use crate::aarch64::structs::{PageLevel, VMSAv864PageDescriptor, VMSAv864TableDescriptor, VirtualAddress, PAGE_SIZE};
use crate::page_allocator::PageAllocator;
use crate::{MemoryAttributes, PagingType};
use crate::{PtError, PtResult};

// This struct will create a the buffer/memory needed for building the page
// tables
#[derive(Clone)]
pub struct TestPageAllocator {
    rimpl: Rc<RefCell<TestPageAllocatorImpl>>,
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
            rimpl: Rc::new(RefCell::new(TestPageAllocatorImpl::new(num_pages))),
            paging_type,
            highest_page_level,
            lowest_page_level,
        }
    }

    pub fn pages_allocated(&self) -> u64 {
        self.rimpl.borrow().page_index
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
    pub fn validate_pages(&self, address: u64, size: u64, attributes: u64) {
        let address = VirtualAddress::new(address);
        let start_va = address;
        let end_va = address + size - 1;

        // page index keep track of the global page being used from the memory.
        // This needed for the recursive page walk logic
        let mut page_index = 0;

        // println!("### validating: {} {}", start_va, end_va + 1);
        self.validate_pages_internal(start_va, end_va, self.highest_page_level, &mut page_index, attributes);
    }

    fn validate_pages_internal(
        &self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        page_index: &mut u64,
        attributes: u64,
    ) {
        if level == self.lowest_page_level - 1 {
            return;
        }

        let start_index = start_va.get_index(level);
        let end_index = end_va.get_index(level);
        let page = self.get_page(*page_index).unwrap();
        let mut va = start_va;
        for index in start_index..=end_index {
            unsafe {
                // hex_dump(page.add(index as usize) as *const u8, 8);
                if level == self.lowest_page_level {
                    // For PT entries we actually store the va
                    self.validate_page_entry(page.add(index as usize), va.into(), level, attributes);
                } else {
                    // For non PT entries we actually store the page base physical address from memory
                    self.validate_page_entry(
                        page.add(index as usize),
                        self.get_memory_base().add((PAGE_SIZE as usize) * (*page_index as usize + 1)) as u64,
                        level,
                        attributes,
                    );

                    // We only consume further pages from PageAllocator memory
                    // for page tables higher than PT type
                    *page_index += 1;
                }
            }

            let next_level_start_va = va;
            let curr_va_ceiling = va.round_up(level);
            let next_level_end_va = VirtualAddress::min(curr_va_ceiling, end_va);

            self.validate_pages_internal(
                next_level_start_va,
                next_level_end_va,
                ((level as u64) - 1).into(),
                page_index,
                attributes,
            );

            va = va.get_next_va(level);
        }
    }

    fn validate_page_entry(
        &self,
        entry_ptr: *const u64,
        expected_page_base: u64,
        level: PageLevel,
        expected_attributes: u64,
    ) {
        unsafe {
            let table_base = *entry_ptr;

            if self.paging_type == PagingType::AArch64PageTable4KB {
                match level {
                    PageLevel::Lvl0 | PageLevel::Lvl1 | PageLevel::Lvl2 => {
                        let page_base: u64 =
                            VMSAv864TableDescriptor::from_bits(table_base).get_canonical_page_table_base().into();
                        let attributes = VMSAv864TableDescriptor::from_bits(table_base).get_attributes();
                        assert_eq!(page_base, expected_page_base);
                        assert_eq!(attributes, 0); // we don't set any attributes on higher level page table entries
                    }
                    PageLevel::Lvl3 => {
                        let page_base: u64 =
                            VMSAv864PageDescriptor::from_bits(table_base).get_canonical_page_table_base().into();
                        let attributes = VMSAv864PageDescriptor::from_bits(table_base).get_attributes();
                        // Ignore memory cache bits
                        let attributes = attributes & (!MemoryAttributes::CacheAttributeMask.bits());
                        assert_eq!(page_base, expected_page_base);
                        assert_eq!(attributes, expected_attributes);
                    }
                    _ => panic!("Unsupported page level"),
                };
            }

            // Compare the actual page base address populated in the entry with
            // the expected page base address
            // println!("{:016X} {:016X}", page_base, expected_page_base);
            // assert_eq!(page_base, expected_page_base);
            // assert_eq!(attributes, expected_attributes);
        }
    }

    fn get_memory_base(&self) -> *const u8 {
        self.rimpl.borrow().get_memory_base()
    }

    fn get_page(&self, index: u64) -> PtResult<*const u64> {
        self.rimpl.borrow().get_page(index)
    }
}

impl PageAllocator for TestPageAllocator {
    fn allocate_page(&mut self, align: u64, size: u64) -> PtResult<u64> {
        self.rimpl.borrow_mut().allocate_page(align, size)
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

        // println!("page allocated: {}", self.page_index);
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
