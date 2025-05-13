cfg_if::cfg_if! {
    // Do not optimize these sections. Maintainability and readability take
    // priority over everything else.
    if #[cfg(all(not(test), target_arch = "aarch64"))] {
        // Build the lib only for aarch64 when targetting aarch64-unknown-uefi
        pub(crate) mod pagetablestore;
        pub(crate) mod paging;
        pub(crate) mod reg;
        pub(crate) mod structs;
        pub use paging::AArch64PageTable;

        pub(crate) const SIZE_4KB: u64 = 0x1000;
        pub(crate) const SIZE_2MB: u64 = 0x200000;
        pub(crate) const SIZE_1GB: u64 = 0x40000000;
        pub(crate) const SIZE_4GB: u64 = 0x100000000;
        pub(crate) const SIZE_64GB: u64 = 0x1000000000;
        pub(crate) const SIZE_1TB: u64 = 0x10000000000;
        pub(crate) const SIZE_4TB: u64 = 0x400000000000;
        pub(crate) const SIZE_16TB: u64 = 0x100000000000;
        pub(crate) const SIZE_256TB: u64 = 0x1000000000000;
    } else if #[cfg(test)] {
        // Build the lib and its associated tests for all applicable host
        // targets x86_64-pc-windows-msvc | aarch64-pc-windows-msvc |
        // x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu
        pub(crate) mod pagetablestore;
        pub(crate) mod paging;
        pub(crate) mod reg;
        pub(crate) mod structs;
        pub use paging::AArch64PageTable;

        pub(crate) const SIZE_4KB: u64 = 0x1000;
        pub(crate) const SIZE_2MB: u64 = 0x200000;
        pub(crate) const SIZE_1GB: u64 = 0x40000000;
        pub(crate) const SIZE_4GB: u64 = 0x100000000;
        pub(crate) const SIZE_64GB: u64 = 0x1000000000;
        pub(crate) const SIZE_1TB: u64 = 0x10000000000;
        pub(crate) const SIZE_4TB: u64 = 0x400000000000;
        pub(crate) const SIZE_16TB: u64 = 0x100000000000;
        pub(crate) const SIZE_256TB: u64 = 0x1000000000000;

        pub(crate) mod tests;
    }
}
