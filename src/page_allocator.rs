use crate::PtError;

/// PageAllocator trait facilitates `allocate_page()` method for allocating new
/// pages. This trait must be implemented by the consumer of this library.
pub trait PageAllocator {
    /// Allocate aligned pages from physical memory.
    ///
    /// ## Arguments
    /// * `align` - The alignment of the page.
    /// * `size` - The expected size of the page.
    /// * `is_root` - Indicates that the returned page will be used as the page
    ///   table root. This can be used to allow the system to make certain adjustments
    ///   required for the root page on some systems
    ///
    ///  ## Access Requirements
    ///
    /// Prior to the page table being installed, the implementation of this function is
    /// responsible for ensuring that the provided address is valid and accessible
    /// through its identity mapped virtual address.
    ///
    /// After the `install_page_table()` method is called, the implementor of this
    /// trait is only responsible for ensuring that the physical address is valid,
    /// but the identity mapped virtual address does not need to be accessible.
    ///
    /// ## Returns
    ///
    /// * `Result<u64, PtError>` - Physical address of the allocated page.
    ///
    fn allocate_page(&mut self, align: u64, size: u64, is_root: bool) -> Result<u64, PtError>;
}

/// A PageAllocator implementation that always fails to allocate pages. This can be useful when inspecting existing page
/// tables where no new allocations are needed.
#[derive(Default)]
pub struct PageAllocatorStub;

impl PageAllocatorStub {
    /// Create a new PageAllocatorStub.
    pub const fn new() -> Self {
        PageAllocatorStub {}
    }
}

impl PageAllocator for PageAllocatorStub {
    fn allocate_page(&mut self, _align: u64, _size: u64, _is_root: bool) -> Result<u64, PtError> {
        Err(crate::PtError::AllocationFailure)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::structs::PAGE_SIZE;

    #[test]
    fn test_page_allocator_stub() {
        let mut allocator = PageAllocatorStub::new();
        let result = allocator.allocate_page(PAGE_SIZE, PAGE_SIZE, false);
        assert!(result.is_err());
    }
}
