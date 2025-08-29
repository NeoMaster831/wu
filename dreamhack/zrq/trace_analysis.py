import json
from node import Node
from lexer import Block
import logging

# I didn't want to make dependency between decompiler and lexer,
# But I had to. Fuck SOLID.

LOG_PATH = "/home/wane/Chall/Wargame/DH/Reverse/zrq/log.jsonl"  # 파일 경로
traces = []
with open(LOG_PATH, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        traces.append(rec)

ea_base = 0x000055868F600000
logging.basicConfig(level=logging.ERROR)

SKIP_THROUGH = 0
for i, trace in enumerate(traces):
    if i < SKIP_THROUGH:
        continue

    ea = trace['ea']
    # let's build desc first
    desc = {}
    for ctx in trace['context']:
        desc[ctx['ea']] = Node(ctx['ea'], ctx['fd'], ctx['bk'], ctx['fn'], ctx['content'], f"off_{ctx['ea']:X}")
    
    with open(f'cfuncs/sub_{ea:X}.c') as f:
        cfunc = f.read().splitlines()

    print(f"[rdi] {desc[trace['rdi']].label}")
    print(f"[r8] {desc[trace['r8']].label if desc.get(trace['r8']) else hex(trace['r8'])}")
    print(f"[ll] ", end='')
    for v in desc.values():
        print(f"{v.label}->", end='')
    print("...")
    print("[ctx]")
    for v in desc.values():
        print(f"  {v.label}->content: {hex(v.content)}")
    blk = Block(cfunc, desc[trace['rdi']], desc)
    blk.lex()
    print(blk.translated())
    print("\n===========================\n")