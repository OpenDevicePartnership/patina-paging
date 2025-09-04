//! Test utilities and code for the page allocator.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use crate::arch::{PageTableEntry, PageTableHal};
use crate::page_allocator::PageAllocator;
use crate::structs::{PAGE_SIZE, PageLevel, PhysicalAddress, VirtualAddress};
use crate::{MemoryAttributes, PagingType};
use crate::{PtError, PtResult};

// Add this import if get_entry is defined in crate::paging or another module
use crate::paging::PageTableStateWithAddress;
use crate::paging::get_entry;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
use std::rc::Rc;

// This struct will create a the buffer/memory needed for building the page
// tables
#[derive(Clone)]
pub struct TestPageAllocator {
    ref_impl: Rc<RefCell<TestPageAllocatorImpl>>,
    paging_type: PagingType,
}

impl TestPageAllocator {
    pub fn new(num_pages: u64, paging_type: PagingType) -> Self {
        Self { ref_impl: Rc::new(RefCell::new(TestPageAllocatorImpl::new(num_pages))), paging_type }
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
    //        │     │                       │ │LVL4E│                               │
    //        │     │                       │ ├─────┤                               │
    //        │     │                       │ │LVL4E|                               │
    //        │     │                       │ └─────┘                               │
    //        │     │                       └─────────────────────────┐             │
    //        │     │                         ┌─────┐       ┌─────┐   │   ┌─────┐   │   ┌─────┐
    //        │     │                         │LVL4E│       │     │   │   │     │   │   │     │
    // Page 2 ├─────┤◄──────────────────────┐ ├─────┤       ├─────┤   │   ├─────┤   │   ├─────┤
    //        │     │                       │ │LVL4E│       │     │   │   │     │   │   │     │
    //        │     │                       │ ├─────┤       ├─────┤   │   ├─────┤   │   ├─────┤
    //        │     │                       │ │LVL4E│       |LVL3E│   │   |     │   │   │LVL1E│
    //        │     │                       │ ├─────┤       ├─────┤   │   ├─────┤   │   ├─────┤
    //        │     │                       │ │LVL4E|       |LVL3E|   │   │LVL2E|   │   │LVL1E|
    //        │     │                       │ └─────┘       └─────┘   │   └─────┘   │   └─────┘
    //        │     │     ┌───────────────┐ └───────────┐             │             │
    // Page 1 ├─────┤◄────┘     ┌─────┐   │   ┌─────┐   │   ┌─────┐   │   ┌─────┐   │   ┌─────┐
    //        │     │           │     │   │   │LVL4E|   │   |LVL3E|   │   │LVL2E|   │   │LVL1E|
    //        │     │           ├─────┤   │   ├─────┤   │   ├─────┤   │   ├─────┤   │   ├─────┤
    //        │     │           │LVL5E│   │   │LVL4E│   │   |LVL3E│   │   │LVL2E│   │   │     │
    //        │     │           ├─────┤   │   ├─────┤   │   ├─────┤   │   ├─────┤   │   ├─────┤
    //        │     │           │LVL5E│   │   │     │   │   |LVL3E│   │   │     │   │   │     │
    //        │     │           ├─────┤   │   ├─────┤   │   ├─────┤   │   ├─────┤   │   ├─────┤
    //        │     │           │     │   │   │     │   │   │     │   │   │     │   │   │     │
    // Page 0 └─────┘◄──────────└─────┘   └───└─────┘   └───└─────┘   └───└─────┘   └───└─────┘
    //
    //  TestPageAllocator                         Page Tables
    //       Memory
    //
    pub fn validate_pages<Arch: PageTableHal>(&self, address: u64, size: u64, attributes: MemoryAttributes) {
        log::info!("Validating pages from {:#x} to {:#x}", address, address + size);
        let address = VirtualAddress::new(address);
        let start_va = address;
        let end_va = ((address + size).unwrap() - 1).unwrap();

        // page index keep track of the global page being used from the memory.
        // This needed for the recursive page walk logic
        let mut page_index = 0;

        self.validate_pages_internal::<Arch>(
            start_va,
            end_va,
            PageLevel::root_level(self.paging_type),
            &mut page_index,
            attributes,
        );
    }

    fn validate_pages_internal<Arch: PageTableHal>(
        &self,
        start_va: VirtualAddress,
        end_va: VirtualAddress,
        level: PageLevel,
        page_index: &mut u64,
        attributes: MemoryAttributes,
    ) {
        log::info!("Validating pages from {start_va} to {end_va} level: {level:?} page_index: {page_index}");
        let start_index = start_va.get_index(level);
        let end_index = end_va.get_index(level);
        let page = self.get_page(*page_index).unwrap();
        let mut va = start_va;
        let zero_pages = PageLevel::root_level(self.paging_type).height() as u64;
        for index in start_index..=end_index {
            let page_base = unsafe {
                // this is a little weird, the 0th page is allocated as the root, then the next N pages are
                // allocated to support the zero VA range, which we don't validate here (a separate test validates)
                match page_index {
                    0 => {
                        let zero_pages = PageLevel::root_level(self.paging_type).height();
                        self.get_memory_base().add((PAGE_SIZE as usize) * (1 + zero_pages)) as u64
                    }
                    _ => self.get_memory_base().add((PAGE_SIZE as usize) * (*page_index as usize + 1)) as u64,
                }
            };
            let leaf =
                unsafe { self.validate_page_entry::<Arch>(page, index, va.into(), page_base, level, attributes) };

            // We only consume further pages from PageAllocator memory
            // for page tables higher than PT type
            if !leaf {
                match page_index {
                    // skip over the root and zero VA pages
                    0 => *page_index += 1 + zero_pages,
                    _ => *page_index += 1,
                }
            }

            let next_level_start_va = va;
            let curr_va_ceiling = va.round_up(level);
            let next_level_end_va = VirtualAddress::min(curr_va_ceiling, end_va);

            if !leaf {
                let next_level = level.next_level().unwrap();
                self.validate_pages_internal::<Arch>(
                    next_level_start_va,
                    next_level_end_va,
                    next_level,
                    page_index,
                    attributes,
                );
            }

            va = va.get_next_va(level).unwrap();
        }
    }

    unsafe fn validate_page_entry<Arch: PageTableHal>(
        &self,
        page_table_ptr: *const u64,
        index: u64,
        virtual_address: u64,
        next_page_table_address: u64,
        level: PageLevel,
        expected_attributes: MemoryAttributes,
    ) -> bool {
        let pte = get_entry::<Arch>(
            level,
            self.paging_type,
            PageTableStateWithAddress::NotSelfMapped(PhysicalAddress::new(page_table_ptr as u64)),
            index,
        )
        .unwrap();

        let page_base: u64 = pte.get_next_address().into();
        let attributes = pte.get_attributes();
        let leaf = pte.points_to_pa(level);

        log::info!(
            "Level: {level:?} PageBase: {page_base:#x}, virtual_address: {virtual_address:#x} next_pt {next_page_table_address:x} leaf: {leaf}",
        );

        if leaf {
            assert_eq!(page_base, virtual_address);
            assert_eq!(attributes, expected_attributes);
        } else {
            assert_eq!(page_base, next_page_table_address);
            assert_eq!(attributes, Arch::DEFAULT_ATTRIBUTES); // We use default attributes for page tables
        }

        leaf
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
        assert!(size == PAGE_SIZE);
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
