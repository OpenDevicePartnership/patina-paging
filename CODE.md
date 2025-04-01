# Code Organization and Build Requirements

The paging crate should be buildable for the following targets, requiring
appropriate conditional compilation to support each:

- **UEFI Targets**: `x86_64-unknown-uefi`, `aarch64-unknown-uefi`
- **Host Targets**: `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`

## Build Strategy

1. **Generic code** should compile for all targets (UEFI + Host).
2. **Architecture-specific library code** should compile for its corresponding
   UEFI target and all host targets.
3. **Test code** should compile only for host targets.

## Directory Structure and Target Compatibility

This is achieved using appropriate conditional compilation guards(3rd column):

<!-- markdownlint-disable MD013 -->
| File/Directory           | Targets Supported                                                | Conditional Compilation           |
| ------------------------ | ---------------------------------------------------------------- | --------------------------------- |
| `src/lib.rs`             | All UEFI Targets + All Host Targets                              | None                              |
| `src/page_allocator.rs`  | All UEFI Targets + All Host Targets                              | None                              |
| `src/aarch64/*.rs`       | AArch64 UEFI Target (`aarch64-unknown-uefi`) + All Hosts Targets | `#[cfg(target_arch = "aarch64")]` |
| `src/x64/*.rs`           | X64 UEFI Target (`x86_64-unknown-uefi`) + All Hosts Targets      | `#[cfg(target_arch = "x86_64")]`  |
| `src/aarch64/tests/*.rs` | All Host Targets                                                 | `#[cfg(test)]`                    |
| `src/x64/tests/*.rs`     | All Host Targets                                                 | `#[cfg(test)]`                    |
<!-- markdownlint-enable MD013 -->

> Note: Some architecture-specific assembly code in lib will be conditionally
> excluded from tests using #[cfg(test)] or #[cfg(not(test))]. If more complex
> conditionals are needed, the code likely requires restructuring.

## Build and Test

- `cargo make build-x64` builds for UEFI x86_64.
- `cargo make build-aarch64` builds for UEFI AArch64.
- `cargo test` builds for the host target and runs the tests.

## PR Readiness

- `cargo make all`
