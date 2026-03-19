//! Tab bar types and deferred actions.

/// Deferred tab actions to avoid mutability issues during UI rendering.
#[derive(Clone, Copy)]
pub(crate) enum TabAction {
    /// Switch to the tab at the given index.
    Select(usize),
    /// Close the tab at the given index.
    Close(usize),
    /// Close all tabs except the one at the given index.
    CloseOthers(usize),
    /// Close all tabs.
    CloseAll,
    /// Close all tabs to the right of the given index.
    CloseRight(usize),
}
