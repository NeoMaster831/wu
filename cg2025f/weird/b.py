from itertools import product

def perm_lane(lane, imm):
    """lane=0..3, imm=2-bit×4  → new lane pos"""
    src = (imm >> (2*lane)) & 3
    return src

def build_pi_one_round(instrs):
    """
    instrs = [
      ('perm', imm1, lane_idx),   # vpermilps
      ('perm', imm2, lane_idx),   # vpermilps
      ('blend', mask, dst_lanes), # vblendmps
      ...
    ]
    """
    pi = [None]*128      # nibble 단위(16×8)
    for blk in range(8):             # 8 × 4byte = 32B
        base = blk*16                # nibble 오프셋
        # 초기 lane 순서 [0,1,2,3]
        order = list(range(4))
        for kind,arg,lidx in instrs[blk]:
            if kind=='perm':
                order = [ perm_lane(i, arg) for i in order ]
            else:                    # blend
                k = arg
                order = [
                   order[i] if not((k>>i)&1) else order[i]^1
                   for i in range(4)
                ]
        # order[i]=source lane → 해당 4 니블 복사
        for i,l in enumerate(order):
            for n in range(4):
                pi[base + i*4 + n] = base + l*4 + n
    return pi

print(pi)