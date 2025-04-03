cfg_if::cfg_if! {
    // Do not optimize these sections. Maintainability and readability take
    // priority over everything else.
    if #[cfg(all(not(test), target_arch = "x86_64"))] {
        // Build the lib only for x64 when targetting x86_64-unknown-uefi.
        pub(crate) mod pagetablestore;
        pub(crate) mod paging;
        pub(crate) mod reg;
        pub(crate) mod structs;
        pub use paging::X64PageTable;

        pub(crate) const SIZE_4KB: u64 = 0x1000;
        pub(crate) const SIZE_2MB: u64 = 0x200000;
        pub(crate) const SIZE_1GB: u64 = 0x40000000;
        pub(crate) const SIZE_512GB: u64 = 0x8000000000;
    } else if #[cfg(test)] {
        // Build the lib and its associated tests for all applicable host
        // targets x86_64-pc-windows-msvc | aarch64-pc-windows-msvc |
        // x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu
        pub(crate) mod pagetablestore;
        pub(crate) mod paging;
        pub(crate) mod reg;
        pub(crate) mod structs;
        pub use paging::X64PageTable;

        pub(crate) const SIZE_4KB: u64 = 0x1000;
        pub(crate) const SIZE_2MB: u64 = 0x200000;
        pub(crate) const SIZE_1GB: u64 = 0x40000000;
        pub(crate) const SIZE_512GB: u64 = 0x8000000000;

        pub(crate) mod tests;
    }
}
