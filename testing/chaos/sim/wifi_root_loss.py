"""Bind a radio interruption to the elected root and observed tree replacement."""

import re

from .paid_relay import eventually
from .paid_settlement import require


NODES = ('n01', 'n02', 'n03')
FIELDS = ('my_node_addr', 'root', 'is_root', 'depth', 'my_coords', 'parent', 'declaration_signed')


def converged(trees, addresses, *, isolated=None):
    require(set(trees) == set(addresses) == set(NODES)
            and len(set(addresses.values())) == 3
            and all(re.fullmatch('[0-9a-f]{32}', address) for address in addresses.values()),
            'root observation changed the participant set')
    require(isolated is None or isolated in NODES, 'unknown isolated root')
    neighbors = {name: {other for other in NODES if abs(int(name[-1])-int(other[-1])) == 1
                       and isolated not in (name, other)} for name in NODES}
    for name, tree in trees.items():
        require(set(FIELDS) <= set(tree) and tree['my_node_addr'] == addresses[name]
                and tree['declaration_signed'] is True and type(tree['is_root']) is bool,
                'tree observation lacks its signed local identity')
        path = tree['my_coords']
        if (not isinstance(path, list) or not path or len(set(path)) != len(path)
                or path[0] != addresses[name] or path[-1] != tree['root']
                or tree['depth'] != len(path)-1 or tree['is_root'] != (len(path) == 1)
                or tree['parent'] != path[min(1, len(path)-1)]):
            return None
        if len(path) > 1:
            parent = next((other for other in neighbors[name] if addresses[other] == path[1]), None)
            if parent is None or trees[parent]['my_coords'] != path[1:]:
                return None
        component = {name}
        while True:
            expanded = component | {other for member in component for other in neighbors[member]}
            if expanded == component:
                break
            component = expanded
        roots = {trees[member]['root'] for member in component}
        if len(roots) != 1 or not roots <= {addresses[member] for member in component}:
            return None
    return trees


class RootLoss:
    def __init__(self, run):
        self.run = run
        self.addresses = {name: bytes(run.state_json(name, 'controller/controller.json')['local']).hex()
                          for name in run.nodes}
        before = eventually('one elected root on the paid line', self.observe, 60)
        root = before['n01']['root']
        self.node, = (name for name, address in self.addresses.items() if address == root)
        self.data = {'node': self.node, 'root_address': root, 'before': before}

    def observe(self, *, isolated=None):
        self.run.monitor.check()
        self.run.check_forwards()
        trees = {}
        for name, node in self.run.nodes.items():
            reply = node.native({'command': 'show_tree'})
            require(reply.get('status') == 'ok', 'native tree observation failed')
            trees[name] = {field: reply['data'][field] for field in FIELDS}
        return converged(trees, self.addresses, isolated=isolated)

    def before_cut(self):
        trees = self.observe()
        require(trees and trees['n01']['root'] == self.data['root_address'],
                'selected radio is no longer the elected root')
        return trees

    def partition(self):
        self.data['isolated'] = eventually('departed root replaced in every surviving component',
                                          lambda: self.observe(isolated=self.node), 90)
        self.run.save()

    def rejoined(self):
        def original_root():
            trees = self.observe()
            return trees if trees and trees['n01']['root'] == self.data['root_address'] else None

        self.data['rejoined'] = eventually('original root and two-hop tree restored', original_root, 90)
        self.run.save()
