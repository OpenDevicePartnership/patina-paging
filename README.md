# CPU Paging Support

## Introduction

This repo include the x64/Arm64 paging logic.

## Public API

The main traits/structs for public consumtion are
`PageTable/PageAllocator/X64PageTable/Aarch64PageTable`.

```rust
pub trait PageTable {
    /// Function to map the designated memory region to with provided
    /// attributes.
    ///
    /// ## Arguments
    /// * `address` - The memory address to map.
    /// * `size` - The memory size to map.
    /// * `attributes` - The memory attributes to map. The acceptable
    ///   input will be EFI_MEMORY_XP, EFI_MEMORY_RO, as well as EFI_MEMORY_UC,
    ///   EFI_MEMORY_WC, EFI_MEMORY_WT, EFI_MEMORY_WB, EFI_MEMORY_UCE
    ///
    /// ## Errors
    /// * Returns `Ok(())` if successful else `Err(PtError)` if failed
    fn map_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> PtResult<()>;

    /// Function to unmap the memory region provided by the caller. The
    /// requested memory region must be fully mapped prior to this call. Unlike
    /// remap_memory_region, the entire region does not have to possess the same
    /// attribute for this operation.
    ///
    /// ## Arguments
    /// * `address` - The memory address to map.
    /// * `size` - The memory size to map.
    ///
    /// ## Errors
    /// * Returns `Ok(())` if successful else `Err(PtError)` if failed
    fn unmap_memory_region(&mut self, address: u64, size: u64) -> PtResult<()>;

    /// Function to remap the memory region provided by the caller. The memory
    /// provided has to be previously mapped and has the same memory attributes
    /// for the entire memory region.
    ///
    /// ## Arguments
    /// * `address` - The memory address to map.
    /// * `size` - The memory size to map.
    /// * `attributes` - The memory attributes to map.
    ///
    /// ## Errors
    /// * Returns `Ok(())` if successful else `Err(PtError)` if failed
    fn remap_memory_region(&mut self, address: u64, size: u64, attributes: u64) -> PtResult<()>;

    /// Function to install the page table from this page table instance.
    ///
    /// ## Errors
    /// * Returns `Ok(())` if successful else `Err(PtError)` if failed
    fn install_page_table(&self) -> PtResult<()>;

    /// Function to query the mapping status and return attribute of supplied
    /// memory region if it is properly and consistently mapped.
    ///
    /// ## Arguments
    /// * `address` - The memory address to map.
    /// * `size` - The memory size to map.
    ///
    /// ## Returns
    /// Returns memory attributes
    ///
    /// ## Errors
    /// * Returns `Ok(u64)` if successful else `Err(PtError)` if failed
    fn query_memory_region(&self, address: u64, size: u64) -> PtResult<u64>;
}
```

```rust
/// PageAllocator trait facilitates `allocate()` method for allocating new pages
pub trait PageAllocator {
    /// Allocate aligned pages from physical memory.
    ///
    /// ## Arguments
    /// * `align` - on x64 this will be 4KB page alignment.
    /// * `size` - on x64 this will be 4KB page size.
    ///
    /// ## Returns
    /// * `PtResult<u64>` - Physcial address of the allocated page.
    fn allocate_page(&mut self, align: u64, size: u64) -> PtResult<u64>;
}
```

## API usage

```rust
    use PageTable;

    let page_allocator = ...;

    let pt = X64PageTable::new(page_allocator, PagingType::Paging4KB4Level)?;

    let attributes = EFI_MEMORY_RP;
    let res = pt.map_memory_region(address, size, attributes);
    ...
    let res = pt.unmap_memory_region(address, size);
    ...
```

## Reference

More reference test cases are in `tests\x64_4kb_page_table_tests.rs`
