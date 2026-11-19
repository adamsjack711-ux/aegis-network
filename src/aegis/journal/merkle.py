"""RFC 9162 §2.1 tree shape, SHA-256 domains and proof ordering."""

from hashlib import sha256

EMPTY = sha256(b"").digest()
MAX_SIZE = 2**63 - 1


def leaf_hash(wire: bytes) -> bytes:
    return sha256(b"\x00" + wire).digest()


def parent(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right).digest()


def split(size: int) -> int:
    return 1 << ((size - 1).bit_length() - 1)


class Tree:
    """Cache complete subtrees. A partial root is assembled from cached nodes."""

    def __init__(self):
        self.nodes: dict[tuple[int, int], bytes] = {}
        self.size = 0

    def append(self, wire: bytes) -> None:
        start, width = self.size, 1
        self.nodes[start, width] = leaf_hash(wire)
        self.size += 1
        while start & width:
            start -= width
            self.nodes[start, width * 2] = parent(
                self.nodes[start, width], self.nodes[start + width, width])
            width *= 2

    def _root(self, start: int, size: int) -> bytes:
        node = self.nodes.get((start, size))
        if node is not None:
            return node
        k = split(size)
        return parent(self._root(start, k), self._root(start + k, size - k))

    def root(self, size: int) -> bytes:
        if not 0 <= size <= self.size:
            raise ValueError("unknown tree size")
        return self._root(0, size) if size else EMPTY

    def inclusion(self, index: int, size: int) -> tuple[bytes, ...]:
        if not 0 <= index < size <= self.size:
            raise ValueError("unknown leaf index")

        def path(start, count, offset):
            if count == 1:
                return ()
            k = split(count)
            if offset < k:
                return path(start, k, offset) + (self._root(start + k, count - k),)
            return path(start + k, count - k, offset - k) + (self._root(start, k),)

        return path(0, size, index)

    def consistency(self, before: int, size: int) -> tuple[bytes, ...]:
        if not 0 <= before <= size <= self.size:
            raise ValueError("unknown tree sizes")

        def path(start, previous, count, known):
            if previous == count:
                return () if known else (self._root(start, count),)
            k = split(count)
            if previous <= k:
                return path(start, previous, k, known) + (self._root(start + k, count - k),)
            return path(start + k, previous - k, count - k, False) + (self._root(start, k),)

        return path(0, before, size, True) if before else ()


def _valid_nodes(proof):
    return len(proof) <= 64 and all(type(node) is bytes and len(node) == 32 for node in proof)


def verify_inclusion(wire, index, size, root, proof) -> bool:
    if not 0 <= index < size <= MAX_SIZE or len(root) != 32 or not _valid_nodes(proof):
        return False
    nodes = iter(proof)

    def descend(offset, count):
        if count == 1:
            return leaf_hash(wire)
        k = split(count)
        if offset < k:
            left = descend(offset, k)
            return parent(left, next(nodes))
        right = descend(offset - k, count - k)
        return parent(next(nodes), right)

    try:
        return descend(index, size) == root and next(nodes, None) is None
    except StopIteration:
        return False


def verify_consistency(before, size, old_root, root, proof) -> bool:
    if (not 0 <= before <= size <= MAX_SIZE or len(old_root) != 32 or len(root) != 32
            or not _valid_nodes(proof)):
        return False
    if before == size:
        return old_root == root and not proof and (size > 0 or root == EMPTY)
    if before == 0:
        return old_root == EMPTY and not proof
    nodes = iter(proof)

    def descend(previous, count, known):
        if previous == count:
            node = old_root if known else next(nodes)
            return node, node
        k = split(count)
        if previous <= k:
            old, new = descend(previous, k, known)
            return old, parent(new, next(nodes))
        old, new = descend(previous - k, count - k, False)
        left = next(nodes)
        return parent(left, old), parent(left, new)

    try:
        return descend(before, size, True) == (old_root, root) and next(nodes, None) is None
    except StopIteration:
        return False
