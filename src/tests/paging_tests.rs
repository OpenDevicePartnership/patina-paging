//! General infrastructure and tests for paging logic, address translation, and page table manipulation.
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use log::{Level, LevelFilter, Metadata, Record};

extern crate std;

use crate::{
    MemoryAttributes, PageTable, PagingType, PtError,
    aarch64::{AArch64PageTable, PageTableArchAArch64},
    arch::{PageTableEntry, PageTableHal},
    page_allocator::PageAllocatorStub,
    structs::{PAGE_SIZE, PageLevel, SIZE_2MB, VirtualAddress},
    tests::test_page_allocator::TestPageAllocator,
    x64::{PageTableArchX64, X64PageTable},
};

use std::slice;

macro_rules! all_archs {
    ($body:expr) => {{
        // Test on x64
        {
            type Arch = PageTableArchX64;
            $body
        }
        // Test on aarch64
        {
            type Arch = PageTableArchAArch64;
            $body
        }
    }};
}

macro_rules! all_configs {
    ($body:expr) => {{
        // Test on x64 - 5 level
        {
            #[allow(unused)]
            type Arch = PageTableArchX64;
            type PageTableType = X64PageTable<TestPageAllocator>;
            #[allow(unused)]
            type PageTableTypeStub = X64PageTable<PageAllocatorStub>;
            let paging_type = PagingType::Paging5Level;
            $body(paging_type)
        }
        // Test on x64 - 4 level
        {
            #[allow(unused)]
            type Arch = PageTableArchX64;
            type PageTableType = X64PageTable<TestPageAllocator>;
            #[allow(unused)]
            type PageTableTypeStub = X64PageTable<PageAllocatorStub>;
            let paging_type = PagingType::Paging4Level;
            $body(paging_type)
        }
        // Test on aarch64 - 4 level
        {
            #[allow(unused)]
            type Arch = PageTableArchAArch64;
            type PageTableType = AArch64PageTable<TestPageAllocator>;
            #[allow(unused)]
            type PageTableTypeStub = AArch64PageTable<PageAllocatorStub>;
            let paging_type = PagingType::Paging4Level;
            $body(paging_type)
        }
    }};
}

// Sample logger for log crate to dump stuff in tests
struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("{}", record.args());
        }
    }

    fn flush(&self) {}
}
static LOGGER: SimpleLogger = SimpleLogger;

fn set_logger() {
    let _ = log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Off));
}

fn subtree_num_pages<Arch: PageTableHal>(
    mut address: VirtualAddress,
    mut size: u64,
    level: PageLevel,
) -> Result<u64, PtError> {
    assert!(address.is_page_aligned());
    assert!(size > 0);
    assert!(VirtualAddress::new(size).is_page_aligned());

    if level.is_lowest_level() {
        return Ok(0);
    }

    let entry_size = level.entry_va_size();
    let size_mask = entry_size - 1;
    let next_level = level.next_level().unwrap();

    let mut pages = 0;
    // Split the range into 3 sections. unaligned prefix, aligned range, unaligned suffix.
    // This helps to optimize for large pages. The prefix and suffix will always use
    // one page to get to the next level.
    if !address.is_level_aligned(level) {
        let prefix_size: u64 = size.min(entry_size - (u64::from(address) & size_mask));
        pages += 1;
        pages += subtree_num_pages::<Arch>(address, prefix_size, next_level)?;
        address = (address + prefix_size)?;
        size -= prefix_size;
    };

    if size >= entry_size {
        let mid_size = size & !size_mask;

        // If this level supports large pages, then no pages are needed for the
        // aligned middle.
        if !Arch::level_supports_pa_entry(level) {
            pages += mid_size / entry_size;
            pages += subtree_num_pages::<Arch>(address, mid_size, next_level)?;
        }

        address = (address + mid_size)?;
        size -= mid_size;
    }

    if size > 0 {
        pages += 1;
        pages += subtree_num_pages::<Arch>(address, size, next_level)?;
    }

    Ok(pages)
}

fn num_page_tables_required<Arch: PageTableHal>(
    address: u64,
    size: u64,
    paging_type: PagingType,
) -> Result<u64, PtError> {
    let address = VirtualAddress::new(address);
    if size == 0 || !address.is_page_aligned() {
        return Err(PtError::UnalignedAddress);
    }

    // Check the memory range is aligned
    if !(address + size)?.is_page_aligned() {
        return Err(PtError::UnalignedAddress);
    }

    // root page table
    let mut pages: u64 = 1;
    // zero VA pages
    pages += PageLevel::root_level(paging_type).height() as u64;
    // The the tree structure before the root.
    pages += subtree_num_pages::<Arch>(address, size, PageLevel::root_level(paging_type))?;

    Ok(pages)
}

fn get_self_mapped_base<Arch: PageTableHal>(paging_type: PagingType) -> u64 {
    Arch::get_self_mapped_base(PageLevel::root_level(paging_type), VirtualAddress::new(0), paging_type)
}

#[test]
fn test_find_num_page_tables() {
    all_archs!({
        // Mapping one page of physical address require 4 page tables(PML4/PDP/PD/PT)
        let address = 0x0;
        let size = PAGE_SIZE; // 4k
        let res = num_page_tables_required::<Arch>(address, size, PagingType::Paging4Level);
        assert!(res.is_ok());
        let table_count = res.unwrap();
        assert_eq!(table_count, 4 + 3);

        // Mapping 511 pages of physical address require 4 page tables(PML4/PDP/PD/PT)
        let address = PAGE_SIZE;
        let size = 511 * PAGE_SIZE;
        let res = num_page_tables_required::<Arch>(address, size, PagingType::Paging4Level);
        assert!(res.is_ok());
        let table_count = res.unwrap();
        assert_eq!(table_count, 4 + 3);

        // Mapping 512 pages of physical address require 3 page tables because of 2mb pages.(PML4/PDP/PD)
        let address = 0x0;
        let size = 512 * PAGE_SIZE;
        let res = num_page_tables_required::<Arch>(address, size, PagingType::Paging4Level);
        assert!(res.is_ok());
        let table_count = res.unwrap();
        assert_eq!(table_count, 3 + 3);

        // Mapping 513 pages of physical address require 4 page tables because it will be 1 2mb mapping and 1 4kb.
        // (PML5(1)/PML4(1)/PDPE(1)/PDP(1)/PT(1))
        let address = 0x0;
        let size = 513 * PAGE_SIZE;
        let res = num_page_tables_required::<Arch>(address, size, PagingType::Paging4Level);
        assert!(res.is_ok());
        let table_count = res.unwrap();
        assert_eq!(table_count, 4 + 3);

        // Mapping 1gb of physical address require 2 page tables because of 1Gb pages.(PML4/PDP)
        let address = 0x0;
        let size = 512 * 512 * PAGE_SIZE;
        let res = num_page_tables_required::<Arch>(address, size, PagingType::Paging4Level);
        assert!(res.is_ok());
        let table_count = res.unwrap();
        assert_eq!(table_count, 2 + 3);

        // Mapping 1 1GbPage + 1 2mb page + 1 4kb page require 4 page tables.(PML4/PDP/PD/PT)
        let address = 0x0;
        let size = (512 * 512 * PAGE_SIZE) + (512 * PAGE_SIZE) + PAGE_SIZE;
        let res = num_page_tables_required::<Arch>(address, size, PagingType::Paging4Level);
        assert!(res.is_ok());
        let table_count = res.unwrap();
        assert_eq!(table_count, 4 + 3);

        // Mapping 2mb starting at 2mb/2 should take 5 pages. (PML4/PDP/PD(1)/PT(2))
        let address = 256 * PAGE_SIZE;
        let size = 512 * PAGE_SIZE;
        let res = num_page_tables_required::<Arch>(address, size, PagingType::Paging4Level);
        assert!(res.is_ok());
        let table_count = res.unwrap();
        assert_eq!(table_count, 5 + 3);

        // Mapping 10Gb starting at 4kb should take 6 pages. (PML4/PDP/PD(2)/PT(2))
        let address = PAGE_SIZE;
        let size = 10 * 512 * 512 * PAGE_SIZE;
        let res = num_page_tables_required::<Arch>(address, size, PagingType::Paging4Level);
        assert!(res.is_ok());
        let table_count = res.unwrap();
        assert_eq!(table_count, 6 + 3);
    });
}

// Memory map tests

#[test]
fn test_map_memory_address_simple() {
    let address = 0;
    let size = 0x400000;

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = Arch::DEFAULT_ATTRIBUTES | MemoryAttributes::ReadOnly;
        let res = pt.map_memory_region(address, size, attributes);

        assert!(res.is_ok());

        assert_eq!(page_allocator.pages_allocated(), num_pages);

        page_allocator.validate_pages::<Arch>(address, size, attributes);
    });
}

#[test]
fn test_map_memory_address_0_to_ffff_ffff() {
    let address = 0;

    all_configs!(|paging_type| {
        let mut size = PAGE_SIZE;

        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = PageTableType::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = Arch::DEFAULT_ATTRIBUTES | MemoryAttributes::ReadOnly;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            log::info!("allocated: {} expected: {}", page_allocator.pages_allocated(), num_pages);
            pt.dump_page_tables(address, size).unwrap();
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            page_allocator.validate_pages::<Arch>(address, size, attributes);

            size <<= 1;
        }
    });
}

#[test]
#[cfg_attr(miri, ignore = "Skipped in miri due to performance issues")]
fn test_map_memory_address_single_page_from_0_to_ffff_ffff() {
    let size = PAGE_SIZE;
    let address_increment = PAGE_SIZE << 3;

    all_configs!(|paging_type| {
        let mut address = 0;
        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = PageTableType::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            assert_eq!(page_allocator.pages_allocated(), num_pages);
            page_allocator.validate_pages::<Arch>(address, size, attributes);

            address += address_increment;
        }
    });
}

#[test]
#[cfg_attr(miri, ignore = "Skipped in miri due to performance issues")]
fn test_map_memory_address_multiple_page_from_0_to_ffff_ffff() {
    let address_increment = PAGE_SIZE << 3;
    let size = PAGE_SIZE << 1;

    all_configs!(|paging_type| {
        let mut address = 0;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = PageTableType::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            assert_eq!(page_allocator.pages_allocated(), num_pages);
            page_allocator.validate_pages::<Arch>(address, size, attributes);

            address += address_increment;
        }
    });
}

#[test]
fn test_map_memory_address_unaligned() {
    let address = 0x1;
    let size = 200;

    all_configs!(|paging_type| {
        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
    });
}

#[test]
fn test_map_memory_address_zero_size() {
    let address = 0x1000;
    let size = 0;

    all_configs!(|paging_type| {
        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
    });
}

// Memory unmap tests

#[test]
fn test_unmap_memory_address_simple() {
    let address = 0x1000;
    let size = PAGE_SIZE * 512 * 512 * 10;

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        let res = pt.unmap_memory_region(address, size);
        assert!(res.is_ok());
    });
}

#[test]
fn test_unmap_memory_address_0_to_ffff_ffff() {
    let address = 0;

    all_configs!(|paging_type| {
        let mut size = PAGE_SIZE;
        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = PageTableType::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = pt.unmap_memory_region(address, size);
            assert!(res.is_ok());
            size <<= 1;
        }
    });
}

#[test]
#[cfg_attr(miri, ignore = "Skipped in miri due to performance issues")]
fn test_unmap_memory_address_single_page_from_0_to_ffff_ffff() {
    let size = PAGE_SIZE;
    let address_increment = PAGE_SIZE << 3;

    all_configs!(|paging_type| {
        let mut address = 0;
        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = PageTableType::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            let res = pt.unmap_memory_region(address, size);
            assert!(res.is_ok());
            address += address_increment;
        }
    });
}

#[test]
#[cfg_attr(miri, ignore = "Skipped in miri due to performance issues")]
fn test_unmap_memory_address_multiple_page_from_0_to_ffff_ffff() {
    let size = PAGE_SIZE << 1;
    let address_increment = PAGE_SIZE << 3;

    all_configs!(|paging_type| {
        let mut address = 0;
        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = PageTableType::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = pt.unmap_memory_region(address, size);
            assert!(res.is_ok());
            address += address_increment;
        }
    });
}

#[test]
fn test_unmap_memory_address_unaligned() {
    let address = 0x1;
    let size = 200;

    all_configs!(|paging_type| {
        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let res = pt.unmap_memory_region(address, size);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
    });
}

#[test]
fn test_unmap_memory_address_zero_size() {
    let address = 0x1000;
    let size = 0;

    all_configs!(|paging_type| {
        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let res = pt.unmap_memory_region(address, size);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
    });
}

#[test]
fn test_unmap_memory_address_with_different_attributes() {
    let address = 0x8000;
    let size = PAGE_SIZE * 4; // 4 pages

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        // Map first two pages with ReadOnly, next two with ExecuteProtect
        let attr1 = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        let attr2 = MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES;

        let res = pt.map_memory_region(address, PAGE_SIZE * 2, attr1);
        assert!(res.is_ok());
        let res = pt.map_memory_region(address + PAGE_SIZE * 2, PAGE_SIZE * 2, attr2);
        assert!(res.is_ok());

        // Unmap the whole region, should succeed even though attributes differ
        let res = pt.unmap_memory_region(address, size);
        assert!(res.is_ok());

        // All pages should now be unmapped
        for i in 0..4 {
            let res = pt.query_memory_region(address + i * PAGE_SIZE, PAGE_SIZE);
            assert!(res.is_err());
        }
    });
}

#[test]
fn test_unmap_memory_address_partially_unmapped() {
    let address = 0x4000;
    let size = PAGE_SIZE * 4; // 4 pages

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        // Map the full range
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());

        // Unmap the second page
        let res = pt.unmap_memory_region(address + PAGE_SIZE, PAGE_SIZE);
        assert!(res.is_ok());

        // Now try to unmap the whole range, which includes already unmapped region
        let res = pt.unmap_memory_region(address, size);
        assert!(res.is_ok());

        // All pages should now be unmapped
        for i in 0..4 {
            let res = pt.query_memory_region(address + i * PAGE_SIZE, PAGE_SIZE);
            assert!(res.is_err());
        }
    });
}

// Memory query tests
#[test]
fn test_query_memory_address_simple() {
    let address = 0x1000;
    let size = PAGE_SIZE * 512 * 512 * 10;

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        let res = pt.query_memory_region(address, size);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), attributes);
    });
}

#[test]
fn test_query_self_map() {
    all_configs!(|paging_type| {
        let address = get_self_mapped_base::<Arch>(paging_type);
        let size = PAGE_SIZE;

        let page_allocator = TestPageAllocator::new(10, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let pt = pt.unwrap();

        let res = pt.query_memory_region(address, size);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), Arch::DEFAULT_ATTRIBUTES);
    });
}

#[test]
fn test_query_memory_address_0_to_ffff_ffff() {
    let address = 0x1000;

    all_configs!(|paging_type| {
        let mut size = PAGE_SIZE;
        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = PageTableType::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = pt.query_memory_region(address, size);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), attributes);
            size <<= 1;
        }
    });
}

#[test]
#[cfg_attr(miri, ignore = "Skipped in miri due to performance issues")]
fn test_query_memory_address_single_page_from_0_to_ffff_ffff() {
    let size = PAGE_SIZE;
    let step = PAGE_SIZE << 3;

    all_configs!(|paging_type| {
        let mut address = 0;
        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = PageTableType::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            let res = pt.query_memory_region(address, size);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), attributes);
            address += step;
        }
    });
}

#[test]
#[cfg_attr(miri, ignore = "Skipped in miri due to performance issues")]
fn test_query_memory_address_multiple_page_from_0_to_ffff_ffff() {
    let size = PAGE_SIZE << 1;
    let step = PAGE_SIZE << 3;

    all_configs!(|paging_type| {
        let mut address = 0;
        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = PageTableType::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = pt.query_memory_region(address, size);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), attributes);
            address += step;
        }
    });
}

#[test]
fn test_query_memory_address_unaligned() {
    let max_pages: u64 = 10;

    all_configs!(|paging_type| {
        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let pt = pt.unwrap();

        let address = 0x1;
        let size = 200;
        let res = pt.query_memory_region(address, size);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
    });
}

#[test]
fn test_query_memory_address_zero_size() {
    let max_pages: u64 = 10;

    all_configs!(|paging_type| {
        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let pt = pt.unwrap();

        let address = 0x1000;
        let size = 0;
        let res = pt.query_memory_region(address, size);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
    });
}

#[test]
fn test_query_memory_address_inconsistent_mappings() {
    let address = 0x1000;
    let size = 0x3000;

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        // Map the first part of the range
        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        let res = pt.map_memory_region(address, PAGE_SIZE, attributes);
        assert!(res.is_ok());

        // Map the last part of the range
        let res = pt.map_memory_region(address + 2 * PAGE_SIZE, PAGE_SIZE, attributes);
        assert!(res.is_ok());

        // Query the entire range, should return InconsistentMappingAcrossRange error
        let res = pt.query_memory_region(address, size);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InconsistentMappingAcrossRange));
    });
}

#[test]
fn test_query_memory_address_inconsistent_mappings_across_2mb_boundary() {
    let address = 0;
    let size = 0x400000;

    all_configs!(|paging_type| {
        let page_allocator = TestPageAllocator::new(0x1000, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        // Map the first 2MB, but not the second 2MB, map in 1MB chunks so that all PTEs are mapped
        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        let res = pt.map_memory_region(address, 0x100000, attributes);
        assert!(res.is_ok());
        let res = pt.map_memory_region(address + 0x100000, 0x100000, attributes);
        assert!(res.is_ok());
        // now unmap so we have valid entries down to PTE, but invalid there
        // let res = pt.unmap_memory_region(address, 0x200000);
        // assert!(res.is_ok());
        let res = pt.map_memory_region(address + 0x200000, 0x100000, attributes);
        assert!(res.is_ok());
        let res = pt.map_memory_region(address + 0x300000, 0x100000, attributes);
        assert!(res.is_ok());
        let res = pt.unmap_memory_region(address + 0x200000, 0x200000);
        assert!(res.is_ok());

        // Query the entire range, should return InconsistentMappingsAcrossRange error
        let res = pt.query_memory_region(address, size);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InconsistentMappingAcrossRange));

        // Now unmap the first 2MB and map the second 2MB
        let res = pt.unmap_memory_region(address, 0x200000);
        assert!(res.is_ok());

        let res = pt.map_memory_region(address + 0x200000, 0x100000, attributes);
        assert!(res.is_ok());
        let res = pt.map_memory_region(address + 0x300000, 0x100000, attributes);
        assert!(res.is_ok());

        // Query the entire range, should return InconsistentMappingsAcrossRange error
        let res = pt.query_memory_region(address, size);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InconsistentMappingAcrossRange));
    });
}

// Memory remap tests
#[test]
fn test_remap_memory_address_simple() {
    let address = 0x1000;
    let size = PAGE_SIZE * 512 * 512 * 10;

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        let attributes = MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
    });
}

#[test]
fn test_remap_memory_address_0_to_ffff_ffff() {
    let address = 0;

    all_configs!(|paging_type| {
        let mut size = PAGE_SIZE;

        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = PageTableType::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let attributes = MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            size <<= 1;
        }
    });
}

#[test]
#[cfg_attr(miri, ignore = "Skipped in miri due to performance issues")]
fn test_remap_memory_address_single_page_from_0_to_ffff_ffff() {
    let address_increment = PAGE_SIZE << 3;
    let size = PAGE_SIZE;

    all_configs!(|paging_type| {
        let mut address = 0;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = PageTableType::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            let attributes = MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            address += address_increment;
        }
    });
}

#[test]
#[cfg_attr(miri, ignore = "Skipped in miri due to performance issues")]
fn test_remap_memory_address_multiple_page_from_0_to_ffff_ffff() {
    let address_increment = PAGE_SIZE << 3;
    let size = PAGE_SIZE << 1;

    all_configs!(|paging_type| {
        let mut address = 0;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);
            let pt = PageTableType::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let attributes = MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            address += address_increment;
        }
    });
}

#[test]
fn test_remap_memory_address_unaligned() {
    let address = 0x1;
    let size = 200;

    all_configs!(|paging_type| {
        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
    });
}

#[test]
fn test_remap_memory_address_zero_size() {
    let address = 0x1000;
    let size = 0;

    all_configs!(|paging_type| {
        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
    });
}

#[test]
fn test_remap_memory_address_mixed_attributes() {
    // This test maps a range with mixed attributes, then remaps the entire range with a single attribute.
    let base_address = 0x3000;
    let total_size = PAGE_SIZE * 4; // 4 pages

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(base_address, total_size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        // Map each page with different attributes
        let attrs = [
            MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES,
            MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES,
            MemoryAttributes::empty() | Arch::DEFAULT_ATTRIBUTES,
            MemoryAttributes::ReadOnly | MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES,
        ];

        for i in 0..4 {
            let addr = base_address + i * PAGE_SIZE;
            let res = pt.map_memory_region(addr, PAGE_SIZE, attrs[i as usize]);
            assert!(res.is_ok());
        }

        // Confirm each page has the expected attribute
        for i in 0..4 {
            let addr = base_address + i * PAGE_SIZE;
            let res = pt.query_memory_region(addr, PAGE_SIZE);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), attrs[i as usize]);
        }

        // Remap the entire range with a single attribute
        let new_attr = MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES;
        let res = pt.map_memory_region(base_address, total_size, new_attr);
        assert!(res.is_ok());

        // Confirm all pages now have the new attribute
        for i in 0..4 {
            let addr = base_address + i * PAGE_SIZE;
            let res = pt.query_memory_region(addr, PAGE_SIZE);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), new_attr);
        }
    });
}

#[test]
fn test_remap_memory_address_partially_mapped_range() {
    // This test maps a range where the first half is already mapped with one attribute,
    // the second half is unmapped, and then remaps the entire range with a new attribute.
    let base_address = 0x2000;
    let total_size = PAGE_SIZE * 4; // 4 pages
    let half_size = PAGE_SIZE * 2;

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(base_address, total_size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attr_initial = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        let attr_new = MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES;

        // Map only the first half of the range
        let res = pt.map_memory_region(base_address, half_size, attr_initial);
        assert!(res.is_ok());

        // Confirm first half is mapped, second half is unmapped
        for i in 0..4 {
            let addr = base_address + i * PAGE_SIZE;
            let res = pt.query_memory_region(addr, PAGE_SIZE);
            if i < 2 {
                assert!(res.is_ok());
                assert_eq!(res.unwrap(), attr_initial);
            } else {
                assert!(res.is_err());
            }
        }

        // Now map the entire range with new attributes (should overwrite old and fill unmapped)
        let res = pt.map_memory_region(base_address, total_size, attr_new);
        assert!(res.is_ok());

        // Confirm all pages are mapped with the new attributes
        for i in 0..4 {
            let addr = base_address + i * PAGE_SIZE;
            let res = pt.query_memory_region(addr, PAGE_SIZE);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), attr_new);
        }
    });
}

#[test]
fn test_from_existing_page_table() {
    let address = 0x1000;
    let size = PAGE_SIZE * 512 * 512 * 10;

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone().clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        // Create a new page table from the existing one
        let page_allocator = PageAllocatorStub::new();
        let new_pt =
            unsafe { PageTableTypeStub::from_existing(pt.into_page_table_root(), page_allocator, paging_type) };
        assert!(new_pt.is_ok());
        let new_pt = new_pt.unwrap();

        // Validate the new page table
        let res = new_pt.query_memory_region(address, size);
        println!("res: {res:?}");
        assert!(res.is_ok());
    });
}

#[test]
fn test_dump_page_tables() {
    let address = 0;
    let size = 0x8000;

    set_logger();

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());

        pt.dump_page_tables(address, size).unwrap();
    });
}

#[test]
#[cfg_attr(miri, ignore = "Skipped in miri due to performance issues")]
fn test_large_page_splitting() {
    #[derive(Clone, Copy)]
    struct TestRange {
        address: u64,
        size: u64,
    }

    impl TestRange {
        fn as_range(&self) -> core::ops::Range<u64> {
            self.address..self.address + self.size
        }
    }

    #[derive(Clone, Copy)]
    struct TestConfig {
        mapped_range: TestRange,
        split_range: TestRange,
        page_increase: u64,
    }

    let test_configs = [
        TestConfig {
            mapped_range: TestRange { address: 0, size: 0x200000 },
            split_range: TestRange { address: 0, size: 0x1000 },
            page_increase: 1, // 1 2MB page split into 4KB pages, adds 1 PT.
        },
        TestConfig {
            mapped_range: TestRange { address: 0, size: 0x600000 },
            split_range: TestRange { address: 0x100000, size: 0x400000 },
            page_increase: 2, // 3 2MB pages split into 1 2MB with 4KB on either side, adds 2 PT.
        },
        TestConfig {
            mapped_range: TestRange { address: 0, size: 0x40000000 },
            split_range: TestRange { address: 0, size: 0x1000 },
            page_increase: 2, // 1 1GB page split into 4KB + 2MB pages, adds 1PD + 1 PT.
        },
        TestConfig {
            mapped_range: TestRange { address: 0, size: 0x40000000 },
            split_range: TestRange { address: 0, size: 0x200000 },
            page_increase: 1, // 1 1GB page split into 2MB pages, adds 1PD.
        },
        TestConfig {
            mapped_range: TestRange { address: 0, size: 0x40000000 },
            split_range: TestRange { address: 0x1FF000, size: 0x2000 },
            page_increase: 3, // 1 1GB page split into 4KB + 2MB pages along 2 2MB pages, adds 1PD + 2 PT.
        },
    ];

    enum TestAction {
        Unmap,
        Remap,
    }

    all_configs!(|paging_type| {
        let orig_attributes = MemoryAttributes::empty() | Arch::DEFAULT_ATTRIBUTES;
        let remap_attributes = MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES;

        for test_config in test_configs {
            let TestConfig { mapped_range, split_range, page_increase } = test_config;
            for action in [TestAction::Unmap, TestAction::Remap] {
                let num_pages =
                    num_page_tables_required::<Arch>(mapped_range.address, mapped_range.size, paging_type).unwrap();

                let page_allocator = TestPageAllocator::new(num_pages + page_increase, paging_type);
                let pt = PageTableType::new(page_allocator.clone(), paging_type);

                assert!(pt.is_ok());
                let mut pt = pt.unwrap();

                let res = pt.map_memory_region(mapped_range.address, mapped_range.size, orig_attributes);
                assert!(res.is_ok());
                assert_eq!(page_allocator.pages_allocated(), num_pages);

                let res = match action {
                    TestAction::Unmap => pt.unmap_memory_region(split_range.address, split_range.size),
                    TestAction::Remap => pt.map_memory_region(split_range.address, split_range.size, remap_attributes),
                };
                assert!(res.is_ok());
                assert_eq!(page_allocator.pages_allocated(), num_pages + page_increase);

                for page in mapped_range.as_range().step_by(0x1000) {
                    let res = pt.query_memory_region(page, PAGE_SIZE);
                    match action {
                        TestAction::Unmap => {
                            if split_range.as_range().contains(&page) {
                                assert!(res.is_err())
                            } else {
                                assert!(res.is_ok())
                            }
                        }
                        TestAction::Remap => {
                            let check_attributes =
                                if split_range.as_range().contains(&page) { remap_attributes } else { orig_attributes };
                            assert!(res.is_ok());
                            assert_eq!(res.unwrap(), check_attributes);
                        }
                    }
                }
            }
        }
    });
}

#[test]
fn test_map_unmap_remap_large_page_subregion() {
    // This test maps a large page (2MB), does an unmap for that, then maps a 4KB subregion within that range.
    let large_page_size = 0x200000; // 2MB
    let base_address = 0x400000;
    let subregion_offset = 0x10000; // 64KB offset into the large page
    let subregion_address = base_address + subregion_offset;
    let subregion_size = PAGE_SIZE;

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(base_address, large_page_size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages + 1, paging_type); // +1 for possible PT split
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let large_attr = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        let subregion_attr = MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES;

        // Map the full 2MB large page
        let res = pt.map_memory_region(base_address, large_page_size, large_attr);
        assert!(res.is_ok());

        // Confirm the full range is mapped with large_attr
        for offset in (0..large_page_size).step_by(PAGE_SIZE as usize) {
            let res = pt.query_memory_region(base_address + offset, PAGE_SIZE);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), large_attr);
        }

        // Unmap the full 2MB large page
        let res = pt.unmap_memory_region(base_address, large_page_size);
        assert!(res.is_ok());

        // Confirm the full range is unmapped
        for offset in (0..large_page_size).step_by(PAGE_SIZE as usize) {
            let res = pt.query_memory_region(base_address + offset, PAGE_SIZE);
            assert!(res.is_err());
        }

        // Map a 4KB subregion within the original large page range
        let res = pt.map_memory_region(subregion_address, subregion_size, subregion_attr);
        assert!(res.is_ok());

        // Confirm only the subregion is mapped, rest is unmapped
        for offset in (0..large_page_size).step_by(PAGE_SIZE as usize) {
            let addr = base_address + offset;
            let res = pt.query_memory_region(addr, PAGE_SIZE);
            if addr == subregion_address {
                assert!(res.is_ok());
                assert_eq!(res.unwrap(), subregion_attr);
            } else {
                assert!(res.is_err());
            }
        }
    });
}

#[test]
fn test_install_page_table() {
    let address = 0x1000;

    all_configs!(|paging_type| {
        let page_allocator = TestPageAllocator::new(0x1000, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        // Create some pages before the install, so VA = PA for accessing
        for i in 0..10 {
            let test_address = address + i * PAGE_SIZE;
            let test_size = PAGE_SIZE;
            let test_attributes = match i % 3 {
                0 => Arch::DEFAULT_ATTRIBUTES | MemoryAttributes::ReadOnly,
                1 => Arch::DEFAULT_ATTRIBUTES | MemoryAttributes::empty(),
                _ => Arch::DEFAULT_ATTRIBUTES | MemoryAttributes::ExecuteProtect,
            };

            let res = pt.map_memory_region(test_address, test_size, test_attributes);
            assert!(res.is_ok());

            let res = pt.query_memory_region(test_address, test_size);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), test_attributes);
        }

        let res = pt.install_page_table();
        assert!(res.is_ok());

        // Try mapping some new pages after the install
        for i in 10..20 {
            let test_address = address + i * PAGE_SIZE;
            let test_size = PAGE_SIZE;
            let test_attributes = match i % 3 {
                0 => Arch::DEFAULT_ATTRIBUTES | MemoryAttributes::ReadOnly,
                1 => Arch::DEFAULT_ATTRIBUTES | MemoryAttributes::empty(),
                _ => Arch::DEFAULT_ATTRIBUTES | MemoryAttributes::ExecuteProtect,
            };

            let res = pt.map_memory_region(test_address, test_size, test_attributes);
            if res.is_err() {
                log::error!("Page fault occurred while mapping address: {test_address:#x}");
                continue;
            }

            // Confirm querying the new pages show they are mapped
            let res = pt.query_memory_region(test_address, test_size);
            if res.is_err() {
                log::error!("Page fault occurred while querying address: {test_address:#x}");
                continue;
            }
            assert_eq!(res.unwrap(), test_attributes);
        }

        // Now try remapping some of the originally mapped pages
        for i in 0..2 {
            let test_address = address + i * PAGE_SIZE;
            let test_size = PAGE_SIZE;
            let test_attributes = match i % 3 {
                0 => Arch::DEFAULT_ATTRIBUTES | MemoryAttributes::ReadOnly,
                1 => Arch::DEFAULT_ATTRIBUTES | MemoryAttributes::empty(),
                _ => Arch::DEFAULT_ATTRIBUTES | MemoryAttributes::ExecuteProtect,
            };

            let res = pt.map_memory_region(test_address, test_size, test_attributes);
            if res.is_err() {
                log::error!("Page fault occurred while remapping address: {test_address:#x}");
                continue;
            }

            // Confirm querying the remapped pages show they are remapped
            let res = pt.query_memory_region(test_address, test_size);
            if res.is_err() {
                log::error!("Page fault occurred while querying address: {test_address:#x}");
                continue;
            }
            assert_eq!(res.unwrap(), test_attributes);
        }

        // Now try unmapping some of the original pages
        for i in 2..4 {
            let test_address = address + i * PAGE_SIZE;
            let test_size = PAGE_SIZE;

            let res = pt.unmap_memory_region(test_address, test_size);
            if res.is_err() {
                log::error!("Page fault occurred while unmapping address: {test_address:#x}");
                continue;
            }

            // Confirm querying the unmapped pages show they are unmapped
            let res = pt.query_memory_region(test_address, test_size);
            if res.is_err() {
                log::error!("Page fault occurred while querying address: {test_address:#x}");
                continue;
            }
        }
    });
}

#[test]
fn test_map_large_page_remap_subset_with_same_attributes() {
    // This test maps a large page (2MB) then does another map for a 4KB subregion within that range with the same
    // attributes to ensure no splitting occurs.
    let large_page_size = 0x200000;
    let base_address = 0x400000; // Purposefully choose a 2MB aligned address
    let subregion_size = SIZE_2MB - PAGE_SIZE;

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(base_address, large_page_size, paging_type).unwrap();

        let page_allocator = TestPageAllocator::new(num_pages + 1, paging_type); // +1 for possible PT split
        let pt = PageTableType::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attr = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;

        // Map the full 2MB large page
        let res = pt.map_memory_region(base_address, large_page_size, attr);
        assert!(res.is_ok());

        // Confirm the range is mapped with the expected attributes
        let res = pt.query_memory_region(base_address, SIZE_2MB);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), attr);

        // Remap the subregion with the same attributes
        let res = pt.map_memory_region(base_address, subregion_size, attr);
        assert!(res.is_ok());

        // Confirm we didn't split the large page by walking the page tables manually
        let mut current_level = match paging_type {
            PagingType::Paging5Level => PageLevel::Level5,
            PagingType::Paging4Level => PageLevel::Level4,
        };
        let va = VirtualAddress::new(base_address);
        let mut pt_base = pt.into_page_table_root();

        loop {
            let index = va.get_index(current_level);
            // SAFETY: Architecturally, the page table is laid out as an array of entries of type T, and we are trusting that
            // the base address is valid and points to a page table of the correct type.
            let pt =
                unsafe { slice::from_raw_parts_mut(pt_base as *mut <Arch as PageTableHal>::PTE, Arch::MAX_ENTRIES) };
            let entry = pt.get(index as usize).unwrap();
            if current_level == PageLevel::Level2 {
                // At level 2, should still be a large page entry
                assert!(entry.points_to_pa(current_level));
                break;
            } else {
                assert!(entry.get_present_bit());
                current_level = current_level.next_level().unwrap();
                pt_base = entry.get_next_address().into();
            }
        }
    });
}

#[test]
fn test_iter_mapped_regions_covers_simple_mapping() {
    let address = 0;
    let size = 0x400000; // 4MB

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();
        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let mut pt = PageTableType::new(page_allocator.clone(), paging_type).unwrap();

        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        pt.map_memory_region(address, size, attributes).unwrap();

        let mut total = 0u64;
        let mut count = 0u64;
        for region in pt.iter_mapped_regions(None) {
            // Every reported region must lie within the mapped range.
            assert!(
                region.va >= address && (region.va + region.size) <= address + size,
                "region {region:#x?} escapes the mapped range"
            );
            // The mapping is identity, so the physical and virtual bases match.
            assert_eq!(region.pa, region.va, "expected identity mapping for region {region:#x?}");
            // Effective attributes must match what was mapped (no restrictive parents).
            assert_eq!(region.attributes, attributes, "unexpected attributes for region {region:#x?}");
            total += region.size;
            count += 1;
        }

        assert_eq!(total, size, "iterated regions must cover the full mapping exactly");
        assert!(count >= 1, "expected at least one mapped region");
    });
}

#[test]
fn test_iter_mapped_regions_skips_reserved_entries() {
    // A freshly created table contains only the crate's reserved self-map and
    // zero-VA entries, which must never be reported as genuine mappings.
    all_configs!(|paging_type| {
        let page_allocator = TestPageAllocator::new(16, paging_type);
        let pt = PageTableType::new(page_allocator.clone(), paging_type).unwrap();

        assert_eq!(
            pt.iter_mapped_regions(None).count(),
            0,
            "an unmapped table must yield no regions (self-map/zero-VA skipped)"
        );
    });
}

#[test]
fn test_iter_mapped_regions_multiple_disjoint() {
    let region_a = (0x40000000u64, SIZE_2MB); // 1GB base, read-only
    let region_b = (0x80000000u64, SIZE_2MB); // 2GB base, execute-protected

    all_configs!(|paging_type| {
        // Sum of the per-region requirements is a safe over-estimate of the
        // pages needed when both are mapped into the same table.
        let pages_a = num_page_tables_required::<Arch>(region_a.0, region_a.1, paging_type).unwrap();
        let pages_b = num_page_tables_required::<Arch>(region_b.0, region_b.1, paging_type).unwrap();
        let page_allocator = TestPageAllocator::new(pages_a + pages_b, paging_type);
        let mut pt = PageTableType::new(page_allocator.clone(), paging_type).unwrap();

        let attr_a = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        let attr_b = MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES;
        pt.map_memory_region(region_a.0, region_a.1, attr_a).unwrap();
        pt.map_memory_region(region_b.0, region_b.1, attr_b).unwrap();

        let mut total_a = 0u64;
        let mut total_b = 0u64;
        for region in pt.iter_mapped_regions(None) {
            if region.va >= region_a.0 && region.va < region_a.0 + region_a.1 {
                assert_eq!(region.attributes, attr_a, "region A attributes mismatch: {region:#x?}");
                total_a += region.size;
            } else if region.va >= region_b.0 && region.va < region_b.0 + region_b.1 {
                assert_eq!(region.attributes, attr_b, "region B attributes mismatch: {region:#x?}");
                total_b += region.size;
            } else {
                panic!("unexpected region outside the mapped ranges: {region:#x?}");
            }
        }

        assert_eq!(total_a, region_a.1, "region A was not fully covered");
        assert_eq!(total_b, region_b.1, "region B was not fully covered");
    });
}

#[test]
fn test_iter_mapped_regions_canonicalizes_high_half() {
    // Mapping in the higher half forces the iterator to sign-extend the
    // additively-computed virtual address back into canonical form. x64
    // 5-level paging is used because it cleanly supports a higher-half identity
    // mapping at this base.
    let paging_type = PagingType::Paging5Level;
    let address = 0xFF00_0000_0000_0000u64;
    let size = SIZE_2MB;

    let num_pages = num_page_tables_required::<PageTableArchX64>(address, size, paging_type).unwrap();
    let page_allocator = TestPageAllocator::new(num_pages, paging_type);
    let mut pt = X64PageTable::new(page_allocator.clone(), paging_type).unwrap();

    let attributes = MemoryAttributes::ReadOnly;
    pt.map_memory_region(address, size, attributes).unwrap();

    let mut total = 0u64;
    let mut min_va = u64::MAX;
    for region in pt.iter_mapped_regions(None) {
        assert!(
            region.va >= address && (region.va + region.size) <= address + size,
            "region {region:#x?} escapes the mapped range starting at {address:#x}"
        );
        min_va = min_va.min(region.va);
        total += region.size;
    }

    assert_eq!(min_va, address, "iterator must report canonical higher-half VAs");
    assert_eq!(total, size, "iterated regions must cover the full mapping");
}

#[test]
fn test_iter_mapped_regions_reports_reserved_indices_for_foreign_table() {
    // The iterator only skips the reserved self-map and zero-VA root indices when the root self-map
    // entry actually points back to the page table base (i.e. a table created and self-mapped by this
    // crate). For a page table not created by this crate, those indices may hold genuine mappings and
    // must be reported rather than silently dropped.
    use crate::structs::{SELF_MAP_INDEX, ZERO_VA_INDEX};

    let paging_type = PagingType::Paging4Level;
    let address = 0u64;
    let size = SIZE_2MB;

    let num_pages = num_page_tables_required::<PageTableArchX64>(address, size, paging_type).unwrap();
    let page_allocator = TestPageAllocator::new(num_pages, paging_type);
    let mut pt = X64PageTable::new(page_allocator.clone(), paging_type).unwrap();

    // Map a single genuine region so the table has at least one real leaf to report and a valid
    // intermediate sub-table chain at root index 0.
    let attributes = MemoryAttributes::ReadOnly;
    pt.map_memory_region(address, size, attributes).unwrap();

    // While self-mapped detection holds, the reserved root entries are skipped: only the genuine
    // mapping is reported.
    let self_mapped_count = pt.iter_mapped_regions(None).count();
    assert_eq!(self_mapped_count, 1, "self-mapped table should report only the genuine mapping");

    let base = pt.into_page_table_root();

    // Make this look like a page table not created by this crate by pointing the reserved root
    // indices at the genuine, valid sub-table chain already built for index 0. This keeps the walk
    // memory-safe (it descends into real allocated tables) while ensuring the root self-map entry no
    // longer points back to `base`, so the iterator must not skip the reserved indices.
    // SAFETY: `base` is the root of a valid page table we just created; we index within its bounds.
    let root = unsafe {
        slice::from_raw_parts_mut(base as *mut <PageTableArchX64 as PageTableHal>::PTE, PageTableArchX64::MAX_ENTRIES)
    };
    let genuine_root_entry = root[0];
    assert!(genuine_root_entry.get_present_bit(), "root index 0 should be present after mapping");
    root[SELF_MAP_INDEX as usize] = genuine_root_entry;
    root[ZERO_VA_INDEX as usize] = genuine_root_entry;

    // Reopen the same physical table as a foreign table. Its self-map entry no longer points to the
    // base, so the iterator must not skip the reserved indices and instead reports the leaves reached
    // through them.
    // SAFETY: `base` points to the valid page table constructed above.
    let foreign = unsafe { X64PageTable::from_existing(base, page_allocator.clone(), paging_type).unwrap() };

    let foreign_count = foreign.iter_mapped_regions(None).count();
    assert!(
        foreign_count > self_mapped_count,
        "foreign table must report the reserved-index entries instead of skipping them \
         (self-mapped: {self_mapped_count}, foreign: {foreign_count})"
    );
}

#[test]
fn test_iter_mapped_regions_start_address_skips_earlier() {
    // Two disjoint mappings. Starting the walk at the second region's base must skip the first
    // region entirely and report only the second.
    let region_a = (0x40000000u64, SIZE_2MB); // 1GB, read-only
    let region_b = (0x80000000u64, SIZE_2MB); // 2GB, execute-protected

    all_configs!(|paging_type| {
        let pages_a = num_page_tables_required::<Arch>(region_a.0, region_a.1, paging_type).unwrap();
        let pages_b = num_page_tables_required::<Arch>(region_b.0, region_b.1, paging_type).unwrap();
        let page_allocator = TestPageAllocator::new(pages_a + pages_b, paging_type);
        let mut pt = PageTableType::new(page_allocator.clone(), paging_type).unwrap();

        let attr_a = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        let attr_b = MemoryAttributes::ExecuteProtect | Arch::DEFAULT_ATTRIBUTES;
        pt.map_memory_region(region_a.0, region_a.1, attr_a).unwrap();
        pt.map_memory_region(region_b.0, region_b.1, attr_b).unwrap();

        // Starting at region B's base, region A must not appear.
        let mut total_b = 0u64;
        let mut count = 0u64;
        for region in pt.iter_mapped_regions(Some(region_b.0)) {
            assert!(region.va >= region_b.0, "region {region:#x?} precedes the requested start {:#x}", region_b.0);
            assert_eq!(region.attributes, attr_b, "only region B should be reported: {region:#x?}");
            total_b += region.size;
            count += 1;
        }
        assert!(count >= 1, "expected region B to be reported");
        assert_eq!(total_b, region_b.1, "region B must be fully covered starting at its base");
    });
}

#[test]
fn test_iter_mapped_regions_start_within_region() {
    // A start address that falls inside a mapped region must still report that region; the reported
    // VA may begin before the requested start.
    let address = 0x40000000u64; // 1GB
    let size = 0x400000u64; // 4MB

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();
        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let mut pt = PageTableType::new(page_allocator.clone(), paging_type).unwrap();

        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        pt.map_memory_region(address, size, attributes).unwrap();

        // Start one page into the mapping; the containing region must still be reported first.
        let start = address + PAGE_SIZE;
        let first = pt.iter_mapped_regions(Some(start)).next().expect("expected at least one region");
        assert!(
            first.va <= start && start < first.va + first.size,
            "first region {first:#x?} must contain the start address {start:#x}"
        );
    });
}

#[test]
fn test_iter_mapped_regions_start_zero_matches_none() {
    // Passing Some(0) must behave identically to None: the entire table is walked.
    let address = 0u64;
    let size = 0x400000u64; // 4MB

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();
        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let mut pt = PageTableType::new(page_allocator.clone(), paging_type).unwrap();

        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        pt.map_memory_region(address, size, attributes).unwrap();

        let none_regions: std::vec::Vec<_> = pt.iter_mapped_regions(None).collect();
        let some_zero_regions: std::vec::Vec<_> = pt.iter_mapped_regions(Some(0)).collect();
        assert!(!none_regions.is_empty(), "expected at least one region");
        assert_eq!(none_regions, some_zero_regions, "Some(0) must match None");
    });
}

#[test]
fn test_iter_mapped_regions_start_after_all_mappings_is_empty() {
    // A start address beyond every mapping must yield no regions.
    let address = 0x40000000u64; // 1GB
    let size = SIZE_2MB;

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(address, size, paging_type).unwrap();
        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let mut pt = PageTableType::new(page_allocator.clone(), paging_type).unwrap();

        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        pt.map_memory_region(address, size, attributes).unwrap();

        // Begin past the end of the single mapping.
        let start = address + size;
        assert_eq!(
            pt.iter_mapped_regions(Some(start)).count(),
            0,
            "no regions should be reported when starting past every mapping"
        );
    });
}

#[test]
fn test_iter_mapped_regions_start_address_high_half() {
    // A canonical higher-half start address must be normalized so the higher-half mapping is still
    // located and reported. x64 5-level paging cleanly supports a higher-half identity mapping here.
    let paging_type = PagingType::Paging5Level;
    let address = 0xFF00_0000_0000_0000u64;
    let size = SIZE_2MB;

    let num_pages = num_page_tables_required::<PageTableArchX64>(address, size, paging_type).unwrap();
    let page_allocator = TestPageAllocator::new(num_pages, paging_type);
    let mut pt = X64PageTable::new(page_allocator.clone(), paging_type).unwrap();

    let attributes = MemoryAttributes::ReadOnly;
    pt.map_memory_region(address, size, attributes).unwrap();

    // Starting exactly at the higher-half base must report the mapping with a canonical VA.
    let mut total = 0u64;
    let mut count = 0u64;
    for region in pt.iter_mapped_regions(Some(address)) {
        assert!(
            region.va >= address && (region.va + region.size) <= address + size,
            "region {region:#x?} escapes the mapped range starting at {address:#x}"
        );
        total += region.size;
        count += 1;
    }
    assert!(count >= 1, "expected the higher-half mapping to be reported");
    assert_eq!(total, size, "iterated regions must cover the full higher-half mapping");
}

#[test]
fn test_iter_mapped_regions_start_seeks_deep_non_root_index() {
    // Pin down the "seek directly to the target index" behavior at a non-root level. Eight contiguous
    // 2MB pages populate a single L2 table (indices 0..8). Starting five entries in must skip L2[0..5]
    // entirely and land exactly on L2[5], proving the lazy per-level seek works once the traversal
    // stack has descended below the root rather than only at index 0.
    let base = 0x40000000u64; // 1GB-aligned: the eight 2MB pages share one L2 table.
    let size = 8 * SIZE_2MB;

    all_configs!(|paging_type| {
        let num_pages = num_page_tables_required::<Arch>(base, size, paging_type).unwrap();
        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let mut pt = PageTableType::new(page_allocator.clone(), paging_type).unwrap();

        let attributes = MemoryAttributes::ReadOnly | Arch::DEFAULT_ATTRIBUTES;
        pt.map_memory_region(base, size, attributes).unwrap();

        // Start at the sixth 2MB page; the walk must skip the first five L2 entries and begin at L2[5].
        let start = base + 5 * SIZE_2MB;
        let regions: std::vec::Vec<_> = pt.iter_mapped_regions(Some(start)).map(|r| (r.va, r.size)).collect();

        assert_eq!(
            regions.len(),
            3,
            "exactly the three pages at or after the start must remain (L2[5..8]): {regions:#x?}"
        );
        assert_eq!(regions[0].0, base + 5 * SIZE_2MB, "first region must be the entry containing the start");
        assert_eq!(regions[1].0, base + 6 * SIZE_2MB, "second region must follow contiguously");
        assert_eq!(regions[2].0, base + 7 * SIZE_2MB, "third region must follow contiguously");
        let total: u64 = regions.iter().map(|(_, s)| *s).sum();
        assert_eq!(total, 3 * SIZE_2MB, "exactly three 2MB pages must remain after the deep seek");
    });
}
