pub trait Slot {
    fn is_justifiable_after(&self, target: u64) -> bool;
}

impl Slot for u64 {
    /// Checks if this slot is a valid candidate for justification after a
    /// given finalized slot.
    ///
    /// Following the 3SF-mini specification, a slot is justifiable if its
    /// distance from the last finalized slot is less than or equal to 5,
    /// is a perfect square or a pronic number.
    fn is_justifiable_after(&self, finalized: u64) -> bool {
        if self < &finalized {
            return false;
        }
        let delta = self - finalized;
        delta <= 5
            || delta.isqrt().pow(2) == delta
            // Pronic numbers have the form n(n+1)
            // For pronic delta = n(n+1), we have:
            //   4 * delta +1 = 4 * n(n+1) + 1 = (2n + 1)^2
            // So we check that 4 * delta + 1 is an odd perfect square
            || ((4 * delta + 1).isqrt().pow(2) == 4 * delta + 1 && (4 * delta + 1).isqrt() % 2 == 1)
    }
}
