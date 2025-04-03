use crate::aarch64::structs::PageLevel;
use crate::aarch64::structs::VirtualAddress;
use crate::PageTable;
use crate::PtError;
use crate::PtResult;
use crate::{
    aarch64::{
        structs::{
            AArch64Descriptor, FOUR_LEVEL_PML4_SELF_MAP_BASE, FRAME_SIZE_4KB, MAX_VA_4_LEVEL, SELF_MAP_INDEX,
            ZERO_VA_4_LEVEL, ZERO_VA_INDEX,
        },
        tests::aarch64_test_page_allocator::TestPageAllocator,
        AArch64PageTable,
    },
    MemoryAttributes, PagingType,
};

fn find_num_entries(start_offset: u64, end_offset: u64, num_parent_level_entries: u64) -> u64 {
    let mut num_entries = 0;
    if num_parent_level_entries > 1 {
        // entries spanning multiple pages
        num_entries += 512 - start_offset; // number of upper entries in first page
        num_entries += (num_parent_level_entries - 2) * 512; // number of entries in between pages
        num_entries += end_offset + 1; // number of lower entries in the last page
    } else {
        // entries do not span multiple pages(end_offset is guaranteed to be higher than start offset)
        num_entries = end_offset - start_offset + 1; // number of entries in the page
    }

    num_entries
}

/// Finds the number of pages that are saved using large pages for the given address
/// range and paging levels compared for using the lowest level.
fn find_large_page_savings(address: u64, size: u64, level: PageLevel, lowest_page_level: PageLevel) -> u64 {
    // The number of large pages in a given address start & length is deterministic
    // based on the alignment of the address to the individual large pages size.
    // Recurse down through levels finding the optimal page size to use.

    if (level == lowest_page_level) || (size == 0) {
        return 0;
    }

    if !level.supports_block_entry() {
        return find_large_page_savings(address, size, level - 1, lowest_page_level);
    }

    let mut savings = 0;
    let alignment = level.entry_va_size();
    let aligned_address = (address + alignment - 1) & !(alignment - 1);

    // If there are no large pages that can be used for the given address range,
    // then continue with the next level.
    if aligned_address + alignment > address + size {
        return find_large_page_savings(address, size, level - 1, lowest_page_level);
    }

    // Split of the unaligned beginning and end and recursive to the next level
    // to find the savings with smaller page sizes.

    savings += find_large_page_savings(address, aligned_address - address, level - 1, lowest_page_level);

    let aligned_end = (address + size) & !(alignment - 1);
    let remainder = (address + size) - aligned_end;

    savings += find_large_page_savings(aligned_end, remainder, level - 1, lowest_page_level);

    // The savings is the number of sub-pages that would be saved by each large page
    // which is 1 for the current level and then 512 for each level below which.
    // e.g. a large page at the third level would save 1 + 512
    let num_large_pages = (aligned_end - aligned_address) / alignment;
    let page_entries: u64 = 512;
    let remaining_levels = level as u64 - lowest_page_level as u64;

    savings += num_large_pages;
    if remaining_levels > 1 {
        savings += num_large_pages * page_entries.pow(remaining_levels as u32 - 1);
    }

    savings
}

pub(crate) fn num_page_tables_required(address: u64, size: u64, paging_type: PagingType) -> PtResult<u64> {
    let address = VirtualAddress::new(address);
    if size == 0 || !address.is_4kb_aligned() {
        return Err(PtError::UnalignedAddress);
    }

    // Check the memory range is aligned
    if !(address + size).is_4kb_aligned() {
        return Err(PtError::UnalignedAddress);
    }

    let start_va = address;
    let end_va = address + size - 1;

    // For the given paging type identify the highest and lowest page levels.
    // This is used during page building to stop the recursion.
    let (highest_page_level, lowest_page_level) = match paging_type {
        PagingType::AArch64PageTable4KB => (PageLevel::Lvl0, PageLevel::Lvl3),
        _ => return Err(PtError::InvalidParameter),
    };

    // The key to calculate the number of tables required for the current level
    // dependents on the number of entries in the parent level. Also, the number
    // of entries in the current level depends on the number of tables in the
    // current level and the current offset(done by `find_num_entries()`).
    let mut num_entries = 0;
    let mut num_tables = 1; // top level table
    let mut total_num_tables = 0;
    for level in ((lowest_page_level as u64)..=(highest_page_level as u64)).rev() {
        let start_offset = start_va.get_index(level.into());
        let end_offset = end_va.get_index(level.into());

        num_entries = find_num_entries(start_offset, end_offset, num_entries);
        total_num_tables += num_tables;
        num_tables = num_entries;
    }

    // The above calculates only the lowest pages, now calculate saving through large
    // pages.
    let savings = find_large_page_savings(address.into(), size, highest_page_level, lowest_page_level);
    total_num_tables -= savings;

    Ok(total_num_tables)
}

#[test]
fn test_find_num_page_tables() {
    // Mapping one page of physical address require 4 page tables.
    let address = 0x0;
    let size = FRAME_SIZE_4KB; // 4k
    let res = num_page_tables_required(address, size, PagingType::AArch64PageTable4KB);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 4);

    // Mapping 511 pages of physical address require 4 page tables.
    let address = FRAME_SIZE_4KB;
    let size = 511 * FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::AArch64PageTable4KB);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 4);

    // Mapping 512 pages of physical address require 3 page tables due to 2MB large pages.
    let address = 0x0;
    let size = 512 * FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::AArch64PageTable4KB);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 3);

    // Mapping 513 pages of physical address require 4 page tables due to 1 2MB page and 1 4KB page.
    let address = 0x0;
    let size = 513 * FRAME_SIZE_4KB + FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::AArch64PageTable4KB);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 4);

    // Mapping 1Gb pages of physical address require 2 page tables due to 1Gb large pages.
    let address = 0x0;
    let size = 512 * 512 * FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::AArch64PageTable4KB);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 2);

    // Mapping 1 1Gb Page + 1 2mb page + 1 4kb page require 4 page tables.
    let address = 0x0;
    let size = (512 * 512 * FRAME_SIZE_4KB) + (512 * FRAME_SIZE_4KB) + FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::AArch64PageTable4KB);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 4);

    // Mapping 2mb starting at 2mb/2 should take 5 pages.
    let address = 256 * FRAME_SIZE_4KB;
    let size = 512 * FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::AArch64PageTable4KB);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 5);

    // Mapping 10Gb starting at 4kb should take 6 pages.
    let address = FRAME_SIZE_4KB;
    let size = 10 * 512 * 512 * FRAME_SIZE_4KB;
    let res = num_page_tables_required(address, size, PagingType::AArch64PageTable4KB);
    assert!(res.is_ok());
    let table_count = res.unwrap();
    assert_eq!(table_count, 6);
}

// Memory map tests

#[test]
fn test_map_memory_address_simple() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0, size: 0x400000 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());

        assert_eq!(page_allocator.pages_allocated(), num_pages);

        page_allocator.validate_pages(address, size, attributes);
    }
}

#[test]
fn test_map_memory_address_not_so_simple() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0, size: 0x400000 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::Uncacheable;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());

        assert_eq!(page_allocator.pages_allocated(), num_pages);

        page_allocator.validate_pages(address, size, attributes);
    }
}

#[test]
fn test_map_memory_address_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0, size: FRAME_SIZE_4KB }];

    for test_config in test_configs {
        let TestConfig { mut size, address, paging_type } = test_config;

        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            if res.is_err() {
                log::info!("addressW: {:x} size: {:x}", address, size);
            }
            assert!(res.is_ok());

            assert_eq!(page_allocator.pages_allocated(), num_pages);

            page_allocator.validate_pages(address, size, attributes);

            size <<= 1;
        }
    }
}

#[test]
fn test_map_memory_address_single_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,

        address_increment: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        address_increment: FRAME_SIZE_4KB,
        size: FRAME_SIZE_4KB,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, address_increment, paging_type } = test_config;
        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            assert_eq!(page_allocator.pages_allocated(), num_pages);
            page_allocator.validate_pages(address, size, attributes);

            address += address_increment;
        }
    }
}

#[test]
fn test_map_memory_address_multiple_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
        address_increment: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        address_increment: FRAME_SIZE_4KB,
        size: FRAME_SIZE_4KB << 1,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, address_increment, paging_type } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            assert_eq!(page_allocator.pages_allocated(), num_pages);
            page_allocator.validate_pages(address, size, attributes);

            address += address_increment;
        }
    }
}

#[test]
fn test_map_memory_address_unaligned() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1, size: 200 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
    }
}

#[test]
fn test_map_memory_address_range_overflow() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [
        // VA range overflows
        TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: MAX_VA_4_LEVEL, size: MAX_VA_4_LEVEL },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
    }
}

#[test]
fn test_map_memory_address_invalid_range() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [
        // VA above the valid address range
        TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: MAX_VA_4_LEVEL + 1, size: FRAME_SIZE_4KB },
    ];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);
        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
    }
}

#[test]
fn test_map_memory_address_zero_size() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1000, size: 0 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
    }
}

// Memory unmap tests

#[test]
fn test_unmap_memory_address_simple() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0x1000,
        size: FRAME_SIZE_4KB * 512 * 512 * 10,
    }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        let res = pt.unmap_memory_region(address, size);
        assert!(res.is_ok());
    }
}

#[test]
fn test_unmap_memory_address_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0, size: FRAME_SIZE_4KB }];

    for test_config in test_configs {
        let TestConfig { mut size, address, paging_type } = test_config;

        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = pt.unmap_memory_region(address, size);
            assert!(res.is_ok());
            size <<= 1;
        }
    }
}

#[test]
fn test_unmap_memory_address_single_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,

        address_increment: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        address_increment: FRAME_SIZE_4KB,
        size: FRAME_SIZE_4KB,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, paging_type, address_increment } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            let res = pt.unmap_memory_region(address, size);
            assert!(res.is_ok());
            address += address_increment;
        }
    }
}

#[test]
fn test_unmap_memory_address_multiple_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
        address_increment: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        address_increment: FRAME_SIZE_4KB,
        size: FRAME_SIZE_4KB << 1,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, paging_type, address_increment } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = pt.unmap_memory_region(address, size);
            assert!(res.is_ok());
            address += address_increment;
        }
    }
}

#[test]
fn test_unmap_memory_address_unaligned() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1, size: 200 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let res = pt.unmap_memory_region(address, size);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
    }
}

#[test]
fn test_unmap_memory_address_zero_size() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1000, size: 0 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;
        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let res = pt.unmap_memory_region(address, size);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
    }
}

// Memory query tests
#[test]
fn test_query_memory_address_simple() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0x1000,
        size: FRAME_SIZE_4KB * 512 * 512 * 10,
    }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        let res = pt.query_memory_region(address, size);
        assert!(res.is_ok());
    }
}

#[test]
fn test_query_memory_address_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs =
        [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1000, size: FRAME_SIZE_4KB }];

    for test_config in test_configs {
        let TestConfig { mut size, address, paging_type } = test_config;
        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = pt.query_memory_region(address, size);
            assert!(res.is_ok());
            size <<= 1;
        }
    }
}

#[test]
fn test_query_memory_address_single_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
        step: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        size: FRAME_SIZE_4KB,
        step: FRAME_SIZE_4KB,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, paging_type, step } = test_config;
        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            let res = pt.query_memory_region(address, size);
            assert!(res.is_ok());
            address += step;
        }
    }
}

#[test]
fn test_query_memory_address_multiple_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
        step: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        size: FRAME_SIZE_4KB << 1,
        step: FRAME_SIZE_4KB,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, paging_type, step } = test_config;
        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = pt.query_memory_region(address, size);
            assert!(res.is_ok());
            address += step;
        }
    }
}

#[test]
fn test_query_memory_address_unaligned() {
    let max_pages: u64 = 10;

    let page_allocator = TestPageAllocator::new(max_pages, PagingType::AArch64PageTable4KB);

    let pt = AArch64PageTable::new(page_allocator.clone(), PagingType::AArch64PageTable4KB);

    assert!(pt.is_ok());
    let pt = pt.unwrap();

    let address = 0x1;
    let size = 200;
    let res = pt.query_memory_region(address, size);
    assert!(res.is_err());
    assert_eq!(res, Err(PtError::UnalignedAddress));
}

#[test]
fn test_query_memory_address_zero_size() {
    let max_pages: u64 = 10;

    let page_allocator = TestPageAllocator::new(max_pages, PagingType::AArch64PageTable4KB);

    let pt = AArch64PageTable::new(page_allocator.clone(), PagingType::AArch64PageTable4KB);

    assert!(pt.is_ok());
    let pt = pt.unwrap();

    let address = 0x1000;
    let size = 0;
    let res = pt.query_memory_region(address, size);
    assert!(res.is_err());
    assert_eq!(res, Err(PtError::InvalidMemoryRange));
}

#[test]
fn test_query_memory_address_inconsistent_mappings() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1000, size: 0x3000 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x4;

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        // Map the first part of the range
        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::Writeback;
        let res = pt.map_memory_region(address, FRAME_SIZE_4KB, attributes);
        assert!(res.is_ok());

        // Map the last part of the range
        let res = pt.map_memory_region(address + 2 * FRAME_SIZE_4KB, FRAME_SIZE_4KB, attributes);
        assert!(res.is_ok());

        // Query the entire range, should return InconsistentMappingAcrossRange error
        let res = pt.query_memory_region(address, size);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InconsistentMappingAcrossRange));
    }
}

#[test]
fn test_query_memory_address_inconsistent_mappings_across_2mb_boundary() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x0, size: 0x400000 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let page_allocator = TestPageAllocator::new(0x1000, paging_type);
        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        // Map the first 2MB, but not the second 2MB, map in 1MB chunks so that all PTEs are mapped
        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::Writeback;
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
    }
}

// Memory remap tests
#[test]
fn test_remap_memory_address_simple() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0x1000,
        size: FRAME_SIZE_4KB * 512 * 512 * 10,
    }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        let attributes = MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback;
        let res = pt.remap_memory_region(address, size, attributes);
        assert!(res.is_ok());
    }
}

#[test]
fn test_remap_memory_address_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0, size: FRAME_SIZE_4KB }];

    for test_config in test_configs {
        let TestConfig { mut size, address, paging_type } = test_config;

        while size < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let attributes = MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback;
            let res = pt.remap_memory_region(address, size, attributes);
            assert!(res.is_ok());
            size <<= 1;
        }
    }
}

#[test]
fn test_remap_memory_address_single_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,

        address_increment: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        address_increment: FRAME_SIZE_4KB,
        size: FRAME_SIZE_4KB,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, address_increment, paging_type } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());

            let attributes = MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback;
            let res = pt.remap_memory_region(address, size, attributes);
            assert!(res.is_ok());
            address += address_increment;
        }
    }
}

#[test]
fn test_remap_memory_address_multiple_page_from_0_to_ffff_ffff() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
        address_increment: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0,
        address_increment: FRAME_SIZE_4KB,
        size: FRAME_SIZE_4KB << 1,
    }];

    for test_config in test_configs {
        let TestConfig { size, mut address, address_increment, paging_type } = test_config;

        while address < 0xffff_ffff {
            let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

            let page_allocator = TestPageAllocator::new(num_pages, paging_type);

            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
            let res = pt.map_memory_region(address, size, attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let attributes = MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback;
            let res = pt.remap_memory_region(address, size, attributes);
            assert!(res.is_ok());
            address += address_increment;
        }
    }
}

#[test]
fn test_remap_memory_address_unaligned() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1, size: 200 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;
        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback;
        let res = pt.remap_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::UnalignedAddress));
    }
}

#[test]
fn test_remap_memory_address_zero_size() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1000, size: 0 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let max_pages: u64 = 10;

        let page_allocator = TestPageAllocator::new(max_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback;
        let res = pt.remap_memory_region(address, size, attributes);
        assert!(res.is_err());
        assert_eq!(res, Err(PtError::InvalidMemoryRange));
    }
}

#[test]
fn test_from_existing_page_table() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig {
        paging_type: PagingType::AArch64PageTable4KB,
        address: 0x1000,
        size: FRAME_SIZE_4KB * 512 * 512 * 10,
    }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);

        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());
        assert_eq!(page_allocator.pages_allocated(), num_pages);

        // Create a new page table from the existing one
        let new_pt =
            unsafe { AArch64PageTable::from_existing(pt.into_page_table_root(), page_allocator.clone(), paging_type) };
        assert!(new_pt.is_ok());
        let new_pt = new_pt.unwrap();

        // Validate the new page table
        let res = new_pt.query_memory_region(address, size);
        assert!(res.is_ok());
    }
}

#[test]
fn test_dump_page_tables() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
        size: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0, size: 0x4000 }];

    for test_config in test_configs {
        let TestConfig { size, address, paging_type } = test_config;

        let num_pages = num_page_tables_required(address, size, paging_type).unwrap() + 0x3;

        let page_allocator = TestPageAllocator::new(num_pages, paging_type);
        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        let attributes = MemoryAttributes::ReadOnly | MemoryAttributes::WriteCombining;
        let res = pt.map_memory_region(address, size, attributes);
        assert!(res.is_ok());

        pt.dump_page_tables(address, size);
    }
}

#[test]
fn test_large_page_splitting() {
    struct TestRange {
        address: u64,
        size: u64,
    }

    impl TestRange {
        fn as_range(&self) -> core::ops::Range<u64> {
            self.address..self.address + self.size
        }
    }

    struct TestConfig {
        paging_type: PagingType,
        mapped_range: TestRange,
        split_range: TestRange,
        page_increase: u64,
    }

    let test_configs = [
        TestConfig {
            paging_type: PagingType::AArch64PageTable4KB,
            mapped_range: TestRange { address: 0, size: 0x200000 },
            split_range: TestRange { address: 0, size: 0x1000 },
            page_increase: 1, // 1 2MB page split into 4KB pages, adds 1 PT.
        },
        TestConfig {
            paging_type: PagingType::AArch64PageTable4KB,
            mapped_range: TestRange { address: 0, size: 0x600000 },
            split_range: TestRange { address: 0x100000, size: 0x400000 },
            page_increase: 2, // 3 2MB pages split into 1 2MB with 4KB on either side, adds 2 PT.
        },
        TestConfig {
            paging_type: PagingType::AArch64PageTable4KB,
            mapped_range: TestRange { address: 0, size: 0x40000000 },
            split_range: TestRange { address: 0, size: 0x1000 },
            page_increase: 2, // 1 1GB page split into 4KB + 2MB pages, adds 1PD + 1 PT.
        },
        TestConfig {
            paging_type: PagingType::AArch64PageTable4KB,
            mapped_range: TestRange { address: 0, size: 0x40000000 },
            split_range: TestRange { address: 0, size: 0x200000 },
            page_increase: 1, // 1 1GB page split into 2MB pages, adds 1PD.
        },
        TestConfig {
            paging_type: PagingType::AArch64PageTable4KB,
            mapped_range: TestRange { address: 0, size: 0x40000000 },
            split_range: TestRange { address: 0x1FF000, size: 0x2000 },
            page_increase: 3, // 1 1GB page split into 4KB + 2MB pages along 2 2MB pages, adds 1PD + 2 PT.
        },
    ];

    enum TestAction {
        Unmap,
        Remap,
    }

    let orig_attributes = MemoryAttributes::empty() | MemoryAttributes::Writeback;
    let remap_attributes = MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback;

    // Test the splitting when remapping.
    for test_config in test_configs {
        let TestConfig { paging_type, mapped_range, split_range, page_increase } = test_config;
        for action in [TestAction::Unmap, TestAction::Remap] {
            let num_pages =
                num_page_tables_required(mapped_range.address, mapped_range.size, paging_type).unwrap() + 0x3;

            let page_allocator = TestPageAllocator::new(num_pages + page_increase, paging_type);
            let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

            assert!(pt.is_ok());
            let mut pt = pt.unwrap();

            let res = pt.map_memory_region(mapped_range.address, mapped_range.size, orig_attributes);
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages);

            let res = match action {
                TestAction::Unmap => pt.unmap_memory_region(split_range.address, split_range.size),
                TestAction::Remap => pt.remap_memory_region(split_range.address, split_range.size, remap_attributes),
            };
            assert!(res.is_ok());
            assert_eq!(page_allocator.pages_allocated(), num_pages + page_increase);

            for page in mapped_range.as_range().step_by(0x1000) {
                let res = pt.query_memory_region(page, FRAME_SIZE_4KB);
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
}

#[test]
fn test_self_map() {
    struct TestConfig {
        paging_type: PagingType,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB }];

    for test_config in test_configs {
        let TestConfig { paging_type } = test_config;

        let page_allocator = TestPageAllocator::new(0x1000, paging_type);
        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let pt = pt.unwrap();

        // we can't query PML4 self map base address(with FOUR_LEVEL_PML4_SELF_MAP_BASE VA), as that
        // va is exclusively reserved for use by the self-map system.
        let res = pt.query_memory_region(FOUR_LEVEL_PML4_SELF_MAP_BASE, FRAME_SIZE_4KB);
        assert!(res.is_err());

        // we can't query the zero VA because in new() it is not mapped on purpose, so we just check we mapped
        // down to the PTE level
        let res = pt.query_memory_region(ZERO_VA_4_LEVEL, FRAME_SIZE_4KB);
        assert!(res.is_err());

        let root = pt.into_page_table_root();

        // now we should see the zero VA and the self map entries in the base page table
        let zero_va_top_level = root + ZERO_VA_INDEX * size_of::<AArch64Descriptor>() as u64;
        assert!(unsafe { *(zero_va_top_level as *const u64) != 0 });

        let zero_va_pdp_level = unsafe { *(zero_va_top_level as *const u64) & !0xFFF };
        assert!(unsafe { *(zero_va_pdp_level as *const u64) != 0 });

        let zero_va_pd_level = unsafe { *(zero_va_pdp_level as *const u64) & !0xFFF };
        assert!(unsafe { *(zero_va_pd_level as *const u64) != 0 });

        let zero_va_pt_level = unsafe { *(zero_va_pd_level as *const u64) & !0xFFF };
        assert!(unsafe { *(zero_va_pt_level as *const u64) != 0 });

        let zero_va_pa = unsafe { *(zero_va_pt_level as *const u64) & !0xFFF };
        assert!(zero_va_pa == 0);

        let self_map_top_level = root + SELF_MAP_INDEX * size_of::<AArch64Descriptor>() as u64;
        assert_eq!((unsafe { *(self_map_top_level as *const u64) } & !0xFFF), root);
    }
}

#[test]
fn test_install_page_table() {
    struct TestConfig {
        paging_type: PagingType,
        address: u64,
    }

    let test_configs = [TestConfig { paging_type: PagingType::AArch64PageTable4KB, address: 0x1000 }];

    for test_config in test_configs {
        let TestConfig { address, paging_type } = test_config;

        let page_allocator = TestPageAllocator::new(0x1000, paging_type);
        let pt = AArch64PageTable::new(page_allocator.clone(), paging_type);

        assert!(pt.is_ok());
        let mut pt = pt.unwrap();

        // Create some pages before the install, so VA = PA for accessing
        for i in 0..10 {
            let test_address = address + i * FRAME_SIZE_4KB;
            let test_size = FRAME_SIZE_4KB;
            let test_attributes = match i % 3 {
                0 => MemoryAttributes::ReadOnly | MemoryAttributes::Writeback,
                1 => MemoryAttributes::Writeback,
                _ => MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback,
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
            let test_address = address + i * FRAME_SIZE_4KB;
            let test_size = FRAME_SIZE_4KB;
            let test_attributes = match i % 3 {
                0 => MemoryAttributes::ReadOnly | MemoryAttributes::Writeback,
                1 => MemoryAttributes::Writeback,
                _ => MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback,
            };

            let res = pt.map_memory_region(test_address, test_size, test_attributes);
            if res.is_err() {
                log::error!("Page fault occurred while mapping address: {:#x}", test_address);
                continue;
            }

            // Confirm querying the new pages show they are mapped
            let res = pt.query_memory_region(test_address, test_size);
            if res.is_err() {
                log::error!("Page fault occurred while querying address: {:#x}", test_address);
                continue;
            }
            assert_eq!(res.unwrap(), test_attributes);
        }

        // Now try remapping some of the originally mapped pages
        for i in 0..2 {
            let test_address = address + i * FRAME_SIZE_4KB;
            let test_size = FRAME_SIZE_4KB;
            let test_attributes = match i % 3 {
                0 => MemoryAttributes::ReadOnly | MemoryAttributes::Writeback,
                1 => MemoryAttributes::Writeback,
                _ => MemoryAttributes::ExecuteProtect | MemoryAttributes::Writeback,
            };

            let res = pt.remap_memory_region(test_address, test_size, test_attributes);
            if res.is_err() {
                log::error!("Page fault occurred while remapping address: {:#x}", test_address);
                continue;
            }

            // Confirm querying the remapped pages show they are remapped
            let res = pt.query_memory_region(test_address, test_size);
            if res.is_err() {
                log::error!("Page fault occurred while querying address: {:#x}", test_address);
                continue;
            }
            assert_eq!(res.unwrap(), test_attributes);
        }

        // Now try unmapping some of the original pages
        for i in 2..4 {
            let test_address = address + i * FRAME_SIZE_4KB;
            let test_size = FRAME_SIZE_4KB;

            let res = pt.unmap_memory_region(test_address, test_size);
            if res.is_err() {
                log::error!("Page fault occurred while unmapping address: {:#x}", test_address);
                continue;
            }

            // Confirm querying the unmapped pages show they are unmapped
            let res = pt.query_memory_region(test_address, test_size);
            if res.is_err() {
                log::error!("Page fault occurred while querying address: {:#x}", test_address);
                continue;
            }
        }
    }
}
