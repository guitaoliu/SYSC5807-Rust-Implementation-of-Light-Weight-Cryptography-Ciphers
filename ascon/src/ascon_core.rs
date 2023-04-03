use core::mem::size_of;

/// Produce mask for padding.
#[inline(always)]
pub const fn pad(n: usize) -> u64 {
    0x80_u64 << (56 - 8 * n)
}

/// Compute round constant
#[inline(always)]
const fn round_constant(round: u64) -> u64 {
    ((0xfu64 - round) << 4) | round
}

/// The state of Ascon's permutation.
///
/// The permutation operates on a state of 320 bits represented as 5 64 bit words.
#[derive(Clone, Copy, Debug, Default)]
pub struct State {
    x: [u64; 5],
}

/// Ascon's round function
const fn round(x: [u64; 5], c: u64) -> [u64; 5] {
    // Add round constant
    let x2 = x[2] ^ c;

    // S-box layer
    let x0 = x[0] ^ x[4];
    let x4 = x[4] ^ x[3];
    let x2 = x2 ^ x[1];

    let t0 = !x0 & x[1];
    let t1 = !x[1] & x2;
    let t2 = !x2 & x[3];
    let t3 = !x[3] & x4;
    let t4 = !x4 & x0;

    let x0 = x0 ^ t1;
    let x1 = x[1] ^ t2;
    let x2 = x2 ^ t3;
    let x3 = x[3] ^ t4;
    let x4 = x4 ^ t0;

    let x1 = x1 ^ x0;
    let x0 = x0 ^ x4;
    let x3 = x3 ^ x2;
    let x2 = !x2;

    // linear layer
    [
        x0 ^ (x0.rotate_right(19)) ^ (x0.rotate_right(28)),
        x1 ^ (x1.rotate_right(61)) ^ (x1.rotate_right(39)),
        x2 ^ (x2.rotate_right(1)) ^ (x2.rotate_right(6)),
        x3 ^ (x3.rotate_right(10)) ^ (x3.rotate_right(17)),
        x4 ^ (x4.rotate_right(7)) ^ (x4.rotate_right(41)),
    ]
}

impl State {
    /// Instantiate new state from the given values.
    pub fn new(x0: u64, x1: u64, x2: u64, x3: u64, x4: u64) -> Self {
        State {
            x: [x0, x1, x2, x3, x4],
        }
    }

    /// Perform permutation with 12 rounds.
    pub fn permute_12(&mut self) {
        self.x = [
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
        ]
        .into_iter()
        .fold(self.x, round);
    }

    pub fn permute_6(&mut self) {
        self.permute_n(6);
    }

    /// Perform a given number (up to 12) of permutations
    pub fn permute_n(&mut self, rounds: usize) {
        assert!(rounds <= 12);

        let start = 12 - rounds;
        self.x = (start..12).fold(self.x, |x, round_index| {
            round(x, round_constant(round_index as u64))
        });
    }
}

impl TryFrom<&[u64]> for State {
    type Error = ();

    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        match value.len() {
            5 => Ok(Self::new(value[0], value[1], value[2], value[3], value[4])),
            _ => Err(()),
        }
    }
}

impl From<&[u64; 5]> for State {
    fn from(value: &[u64; 5]) -> Self {
        Self { x: *value }
    }
}

impl TryFrom<&[u8]> for State {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != core::mem::size_of::<u64>() * 5 {
            return Err(());
        }

        let mut state = Self::default();
        for (src, dst) in value
            .chunks_exact(core::mem::size_of::<u64>())
            .zip(state.x.iter_mut())
        {
            *dst = u64::from_be_bytes(src.try_into().unwrap());
        }
        Ok(state)
    }
}

impl From<&[u8; size_of::<u64>() * 5]> for State {
    fn from(value: &[u8; size_of::<u64>() * 5]) -> Self {
        let mut state = Self::default();
        for (src, dst) in value
            .chunks_exact(core::mem::size_of::<u64>())
            .zip(state.x.iter_mut())
        {
            *dst = u64::from_be_bytes(src.try_into().unwrap());
        }
        state
    }
}

impl AsRef<[u64]> for State {
    fn as_ref(&self) -> &[u64] {
        &self.x
    }
}

impl core::ops::Index<usize> for State {
    type Output = u64;

    #[inline(always)]
    fn index(&self, index: usize) -> &Self::Output {
        &self.x[index]
    }
}

impl core::ops::IndexMut<usize> for State {
    #[inline(always)]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.x[index]
    }
}

impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.x == other.x
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_0to7() {
        assert_eq!(pad(0), 0x8000000000000000);
        assert_eq!(pad(1), 0x80000000000000);
        assert_eq!(pad(2), 0x800000000000);
        assert_eq!(pad(3), 0x8000000000);
        assert_eq!(pad(4), 0x80000000);
        assert_eq!(pad(5), 0x800000);
        assert_eq!(pad(6), 0x8000);
        assert_eq!(pad(7), 0x80);
    }

    #[test]
    fn round_constants() {
        assert_eq!(round_constant(0), 0xf0);
        assert_eq!(round_constant(1), 0xe1);
        assert_eq!(round_constant(2), 0xd2);
        assert_eq!(round_constant(3), 0xc3);
        assert_eq!(round_constant(4), 0xb4);
        assert_eq!(round_constant(5), 0xa5);
        assert_eq!(round_constant(6), 0x96);
        assert_eq!(round_constant(7), 0x87);
        assert_eq!(round_constant(8), 0x78);
        assert_eq!(round_constant(9), 0x69);
        assert_eq!(round_constant(10), 0x5a);
        assert_eq!(round_constant(11), 0x4b);
    }

    #[test]
    fn one_round() {
        let state = round(
            [
                0x0123456789abcdef,
                0x23456789abcdef01,
                0x456789abcdef0123,
                0x6789abcdef012345,
                0x89abcde01234567f,
            ],
            0x1f,
        );
        assert_eq!(
            state,
            [
                0x3c1748c9be2892ce,
                0x5eafb305cd26164f,
                0xf9470254bb3a4213,
                0xf0428daf0c5d3948,
                0x281375af0b294899
            ]
        );
    }

    #[test]
    fn state_permute_12() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        let mut state2 = state;
        state.permute_12();
        state2.permute_n(12);
        assert_eq!(state[0], 0x206416dfc624bb14);
        assert_eq!(state[1], 0x1b0c47a601058aab);
        assert_eq!(state[2], 0x8934cfc93814cddd);
        assert_eq!(state[3], 0xa9738d287a748e4b);
        assert_eq!(state[4], 0xddd934f058afc7e1);

        assert_eq!(state, state2);
    }
}
