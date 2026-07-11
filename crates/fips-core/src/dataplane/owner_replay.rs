const REPLAY_BLOCK_BITS_LOG: u64 = 6;
const REPLAY_BLOCK_BITS: u64 = 1 << REPLAY_BLOCK_BITS_LOG;
const REPLAY_RING_BLOCKS: usize = 1 << 7;
const REPLAY_RING_BLOCKS_U64: u64 = REPLAY_RING_BLOCKS as u64;
const REPLAY_WINDOW_SIZE: u64 = (REPLAY_RING_BLOCKS_U64 - 1) * REPLAY_BLOCK_BITS;
const REPLAY_BLOCK_MASK: u64 = REPLAY_RING_BLOCKS_U64 - 1;
const REPLAY_BIT_MASK: u64 = REPLAY_BLOCK_BITS - 1;

#[derive(Debug)]
struct ReplayWindow {
    highest: Option<u64>,
    ring: [u64; REPLAY_RING_BLOCKS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            ring: [0; REPLAY_RING_BLOCKS],
        }
    }
}

impl ReplayWindow {
    fn clear(&mut self) {
        *self = Self::default();
    }

    fn accept(&mut self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(counter);
            return self.set_counter_bit(counter);
        };

        if counter > highest {
            self.advance(highest, counter);
            self.highest = Some(counter);
            return self.set_counter_bit(counter);
        }

        let behind = highest - counter;
        if behind > REPLAY_WINDOW_SIZE {
            return false;
        }

        self.set_counter_bit(counter)
    }

    fn can_accept(&self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if counter > highest {
            return true;
        }
        let behind = highest - counter;
        behind <= REPLAY_WINDOW_SIZE && self.ring[ring_index(counter)] & counter_bit(counter) == 0
    }

    fn advance(&mut self, highest: u64, counter: u64) {
        let current = counter_block(highest);
        let target = counter_block(counter);
        let mut diff = target - current;
        if diff > REPLAY_RING_BLOCKS_U64 {
            diff = REPLAY_RING_BLOCKS_U64;
        }
        for offset in 1..=diff {
            self.ring[((current + offset) & REPLAY_BLOCK_MASK) as usize] = 0;
        }
    }

    fn set_counter_bit(&mut self, counter: u64) -> bool {
        let index = ring_index(counter);
        let mask = counter_bit(counter);
        let old = self.ring[index];
        self.ring[index] = old | mask;
        old != self.ring[index]
    }
}

fn counter_block(counter: u64) -> u64 {
    counter >> REPLAY_BLOCK_BITS_LOG
}

fn ring_index(counter: u64) -> usize {
    (counter_block(counter) & REPLAY_BLOCK_MASK) as usize
}

fn counter_bit(counter: u64) -> u64 {
    1u64 << (counter & REPLAY_BIT_MASK)
}

#[cfg(test)]
mod replay_window_tests {
    use super::*;

    #[test]
    fn replay_window_tracks_duplicates_window_edges_and_wrapped_blocks() {
        let mut window = ReplayWindow::default();

        assert!(window.accept(10));
        assert!(window.accept(8));
        assert!(window.accept(9));
        assert!(!window.accept(10));
        assert!(!window.accept(8));

        let mut window = ReplayWindow::default();

        assert!(window.accept(1));
        assert!(window.accept(1 + REPLAY_WINDOW_SIZE));
        assert!(!window.accept(1));

        assert!(window.accept(2 + REPLAY_WINDOW_SIZE));
        assert!(!window.accept(1));
        assert!(window.accept(2));

        let mut window = ReplayWindow::default();

        assert!(window.accept(0));
        assert!(window.accept(REPLAY_BLOCK_BITS * REPLAY_RING_BLOCKS_U64));
        assert!(!window.accept(0));
        assert!(window.accept(REPLAY_BLOCK_BITS * REPLAY_RING_BLOCKS_U64 + 1));
    }
}
