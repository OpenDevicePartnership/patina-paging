# CPU Paging Support

## Introduction

This repo include the X64/AArch64 paging logic.

## Public API

The main traits/structs for public consumption are
`PageTable/PageAllocator/X64PageTable/Aarch64PageTable`.

```rust
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct MemoryAttributes: u64 {
        // Memory Caching Attributes
        const Uncacheable       = 0x00000000_00000001u64;
        const WriteCombining    = 0x00000000_00000002u64;
        const WriteThrough      = 0x00000000_00000004u64;
        const Writeback         = 0x00000000_00000008u64;
        const UncacheableExport = 0x00000000_00000010u64;
        const WriteProtect      = 0x00000000_00001000u64;

        // Memory Access Attributes
        const ReadProtect       = 0x00000000_00002000u64;   // Maps to Present bit on X64
        const ExecuteProtect    = 0x00000000_00004000u64;   // Maps to NX bit on X64
        const ReadOnly          = 0x00000000_00020000u64;   // Maps to Read/Write bit on X64


        const CacheAttributesMask = Self::Uncacheable.bits() |
                                    Self::WriteCombining.bits() |
                                    Self::WriteThrough.bits() |
                                    Self::Writeback.bits() |
                                    Self::UncacheableExport.bits() |
                                    Self::WriteProtect.bits();

        const AccessAttributesMask = Self::ReadProtect.bits() |
                                     Self::ExecuteProtect.bits() |
                                     Self::ReadOnly.bits();
    }
}

pub trait PageTable {
    /// Function to map the designated memory region to with provided
    /// attributes.
    ///
    /// ## Arguments
    /// * `address` - The memory address to map.
    /// * `size` - The memory size to map.
    /// * `attributes` - The memory attributes to map. The acceptable
    ///   input will be ExecuteProtect, ReadOnly, as well as Uncacheable,
    ///   WriteCombining, WriteThrough, Writeback, UncacheableExport.
    ///   Compatible attributes can be "Ored"
    ///
    /// ## Errors
    /// * Returns `Ok(())` if successful else `Err(PtError)` if failed
    fn map_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()>;

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
    fn remap_memory_region(&mut self, address: u64, size: u64, attributes: MemoryAttributes) -> PtResult<()>;

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
    /// * Returns `Ok(MemoryAttributes)` if successful else `Err(PtError)` if failed
    fn query_memory_region(&self, address: u64, size: u64) -> PtResult<MemoryAttributes>;
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

    let attributes = MemoryAttributes::ReadOnly;
    let res = pt.map_memory_region(address, size, attributes);
    ...
    let res = pt.unmap_memory_region(address, size);
    ...
```

## Reference

More reference test cases are in `src\tests\x64_paging_tests.rs`
