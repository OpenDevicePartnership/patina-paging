use crate::PtResult;

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
    /// through it's identity mapped virtual address.
    ///
    /// After the `install_page_table()` method is called, the implementor of this
    /// trait is only resposible for ensuring that the physical address is valid,
    /// but the identity mapped virtual address does not need to be accessible.
    ///
    /// ## Returns
    ///
    /// * `PtResult<u64>` - Physical address of the allocated page.
    ///
    fn allocate_page(&mut self, align: u64, size: u64, is_root: bool) -> PtResult<u64>;
}
