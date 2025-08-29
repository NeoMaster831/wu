class Node:
    def __init__(self, ea, fd, bk, unk0, content, label):
        self.ea = ea # This is key.
        self.fd = fd
        self.bk = bk
        self.unk0 = unk0
        self.content = content
        self.label = label
    def free(self):
        return self.fd # return the next malloc's node.
    def __repr__(self): # We can do this becuase it is primitive variables
        return f"Node(ea={self.ea}, fd={self.fd}, bk={self.bk}, unk0={self.unk0}, content={self.content}, label=\'{self.label}\')"
