"""Root-loss evidence must exclude stale roots, loops and shortcut coordinates."""

import copy
import unittest

from sim.wifi_root_loss import converged


ADDRESSES = {f'n{i:02}': f'{i:032x}' for i in range(1, 4)}


def trees(root=1, isolated=None):
    result = {}
    for index in range(1, 4):
        target = index if isolated == 2 or isolated == index else root
        if isolated in (1, 3) and index != isolated:
            target = 2
        step = 1 if target >= index else -1
        path = [ADDRESSES[f'n{i:02}'] for i in range(index, target + step, step)]
        result[f'n{index:02}'] = dict(my_node_addr=path[0], root=path[-1], is_root=len(path) == 1,
                                    depth=len(path)-1, my_coords=path, parent=path[min(1, len(path)-1)],
                                    declaration_signed=True)
    return result


class RootLossTests(unittest.TestCase):
    def test_each_root_position_and_partition_can_converge(self):
        for root in range(1, 4):
            with self.subTest(root=root):
                self.assertTrue(converged(trees(root), ADDRESSES))
                self.assertTrue(converged(trees(root, root), ADDRESSES, isolated=f'n{root:02}'))

    def test_departed_root_is_not_a_replacement(self):
        for root in range(1, 4):
            with self.subTest(root=root):
                self.assertIsNone(converged(trees(root), ADDRESSES, isolated=f'n{root:02}'))

    def test_unknown_identity_unsigned_declaration_and_missing_node_are_rejected(self):
        for change in ('identity', 'unsigned', 'missing'):
            with self.subTest(change=change):
                sample = trees()
                if change == 'identity':
                    sample['n02']['my_node_addr'] = 'f' * 32
                elif change == 'unsigned':
                    sample['n02']['declaration_signed'] = False
                else:
                    del sample['n02']
                with self.assertRaises(RuntimeError):
                    converged(sample, ADDRESSES)

    def test_parent_shortcut_loop_or_split_root_cannot_qualify(self):
        for change in ('parent', 'shortcut', 'loop', 'root'):
            with self.subTest(change=change):
                sample = copy.deepcopy(trees())
                if change == 'parent':
                    sample['n03']['parent'] = ADDRESSES['n01']
                elif change == 'shortcut':
                    sample['n03'].update(parent=ADDRESSES['n01'], depth=1,
                                         my_coords=[ADDRESSES['n03'], ADDRESSES['n01']])
                elif change == 'loop':
                    sample['n03']['my_coords'].insert(1, ADDRESSES['n03'])
                    sample['n03']['depth'] += 1
                else:
                    sample['n03']['root'] = ADDRESSES['n02']
                self.assertIsNone(converged(sample, ADDRESSES))


if __name__ == '__main__':
    unittest.main()
