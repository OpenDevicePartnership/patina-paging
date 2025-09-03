use log::{Level, LevelFilter, Metadata, Record};

use crate::{
    MemoryAttributes, PageTable, PagingType, PtError, PtResult,
    aarch64::{AArch64PageTable, PageTableArchAArch64},
    arch::PageTableHal,
    structs::{PAGE_SIZE, PageLevel, VirtualAddress},
    tests::test_page_allocator::TestPageAllocator,
    x64::{PageTableArchX64, X64PageTable},
};

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
            let paging_type = PagingType::Paging5Level;
            $body(paging_type)
        }
        // Test on x64 - 4 level
        {
            #[allow(unused)]
            type Arch = PageTableArchX64;
            type PageTableType = X64PageTable<TestPageAllocator>;
            let paging_type = PagingType::Paging4Level;
            $body(paging_type)
        }
        // Test on aarch64
        {
            #[allow(unused)]
            type Arch = PageTableArchAArch64;
            type PageTableType = AArch64PageTable<TestPageAllocator>;
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
) -> PtResult<u64> {
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

fn num_page_tables_required<Arch: PageTableHal>(address: u64, size: u64, paging_type: PagingType) -> PtResult<u64> {
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
        let res = pt.remap_memory_region(address, size, attributes);
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
            let res = pt.remap_memory_region(address, size, attributes);
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
            let res = pt.remap_memory_region(address, size, attributes);
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
            let res = pt.remap_memory_region(address, size, attributes);
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
        let res = pt.remap_memory_region(address, size, attributes);
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
        let res = pt.remap_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
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
        let page_allocator = TestPageAllocator::new(0, paging_type);
        let new_pt = unsafe { PageTableType::from_existing(pt.into_page_table_root(), page_allocator, paging_type) };
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
                    TestAction::Remap => {
                        pt.remap_memory_region(split_range.address, split_range.size, remap_attributes)
                    }
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

            let res = pt.remap_memory_region(test_address, test_size, test_attributes);
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
