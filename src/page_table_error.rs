pub type PtResult<T> = Result<T, PtError>;

#[derive(Debug, PartialEq)]
pub enum PtError {
    // Invalid parameter
    InvalidParameter,

    // Out of resources
    OutOfResources,

    // No Mapping
    NoMapping,

    // Incompatible Memory Attributes
    IncompatibleMemoryAttributes,

    // Unaligned Page Base
    UnalignedPageBase,

    // Unaligned Address
    UnalignedAddress,

    // Unaligned Memory Range
    UnalignedMemoryRange,
}
