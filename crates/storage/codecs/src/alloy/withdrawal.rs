use crate::Compact;
use alloy_eips::eip4895::Withdrawal as AlloyWithdrawal;
use alloy_primitives::Address;
use reth_codecs_derive::main_codec;

/// Withdrawal acts as bridge which simplifies Compact implementation for AlloyWithdrawal.
///
/// Notice: Make sure this struct is 1:1 with `alloy_eips::eip4895::Withdrawal`
#[main_codec]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Withdrawal {
    /// Monotonically increasing identifier issued by consensus layer.
    index: u64,
    /// Index of validator associated with withdrawal.
    validator_index: u64,
    /// Target address for withdrawn ether.
    address: Address,
    /// Value of the withdrawal in gwei.
    amount: u64,
}

impl Compact for AlloyWithdrawal {
    fn to_compact<B>(self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let withdrawal = Withdrawal {
            index: self.index,
            validator_index: self.validator_index,
            address: self.address,
            amount: self.amount,
        };
        withdrawal.to_compact(buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (withdrawal, _) = Withdrawal::from_compact(buf, len);
        let alloy_withdrawal = AlloyWithdrawal {
            index: withdrawal.index,
            validator_index: withdrawal.validator_index,
            address: withdrawal.address,
            amount: withdrawal.amount,
        };
        (alloy_withdrawal, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::proptest;

    proptest! {
        #[test]
        fn roundtrip(withdrawal: AlloyWithdrawal) {
            let mut compacted_withdrawal = Vec::<u8>::new();
            let len = withdrawal.to_compact(&mut compacted_withdrawal);
            let (decoded, _) = AlloyWithdrawal::from_compact(&compacted_withdrawal, len);
            assert_eq!(withdrawal, decoded)
        }
    }
}