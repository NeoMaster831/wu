nodes = {}
fulfilled = [None]* 256
class Node:
    def __init__(self, val, leaf=False, one_go_here=None, zero_go_here=None):
        global nodes
        self.leaf = leaf
        self.ogh = one_go_here
        self.zgh = zero_go_here
        self.val = val
        self.id = len(nodes)
        nodes[self.id] = self
        fulfilled[val] = self.id
    def __repr__(self):
        return f"Node(id={self.id}, val={hex(self.val)}, leaf={self.leaf}, ogh_val={hex(nodes[self.ogh].val)}, zgh_val={hex(nodes[self.zgh].val)})"

FILENAME = "quiz_last.zrq"
OUT_FILENAME = "quiz_last.zrq.2"

def build_tree():

    # First, let's read until tree's end
    f = open(FILENAME, "rb")
    a, b = f.read(1), f.read(1)
    offset = 2
    while a != b:
        a, b = b, f.read(1)
        offset += 1
    f.close()

    # Now let's build the tree.
    with open(FILENAME, "rb") as f:
        total_data = f.read()[:offset]
        tree_data = total_data[:-1]
        root = total_data[-3]

    for a, b in zip(tree_data[::2], tree_data[1::2]):
        if fulfilled[a] is None: # we should create a leaf node.
            fulfilled[a] = Node(a, True).id
        if fulfilled[b] is None:
            fulfilled[b] = Node(b, True).id
        fulfilled[a] = Node(a, False, fulfilled[b], fulfilled[a]).id

    root_node = nodes[fulfilled[root]]

    # For the sake, root node is swapped initially. We should fix this.
    root_node.val = nodes[root_node.zgh].val

    return root_node, offset

def bytes_to_bin_string_rev(data):
    return (''.join(f"{byte:08b}" for byte in data))[::-1]

def solve_stage2():
    root_node, file_offset = build_tree()
    print("File offset:", hex(file_offset))
    print("Root node:", root_node)

    with open(FILENAME, "rb") as f:
        f.seek(file_offset)
        data = f.read()
    #print(data)

    binstr = bytes_to_bin_string_rev(data)[6:] # how..

    #print(binstr)
    nd = root_node
    orig = b""
    for i in binstr:
        #print("current node:", nd, i)
        if i == '1': # v1..
            nd = nodes[nd.ogh]
        else: # v2..
            nd = nodes[nd.zgh]
        if nd.leaf:
            orig += bytes([ nd.val ])
            nd = root_node
            #print("Return to root")
    assert(nd == root_node)
    orig = orig[::-1]

    return orig

if __name__ == '__main__':
    orig = solve_stage2()
    with open(OUT_FILENAME, "wb") as f:
        f.write(orig)