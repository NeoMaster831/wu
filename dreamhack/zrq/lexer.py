from node import Node
import logging
import re

ld = lambda x: logging.debug(f"[+] {x}")
li = lambda x: logging.info(f"[+] {x}")
lw = lambda x: logging.warning(f"[!] {x}")
le = lambda x: logging.error(f"[x] {x}")

# 1) 문자열 리터럴 제거: "..." 와 '...' (이스케이프 포함)
STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.DOTALL)

# 2) C/C++ 캐스트 제거
#    (_UNKNOWN ******), (const struct termios *), (__int64), (unsigned __int64),
#    (Node *), (_QWORD *), (off_t *), (size_t) 등 폭넓게 매칭
CAST_RE = re.compile(
    r"""
    \(
        \s*
        (?:                                  # 앞쪽 한정자들
            (?:const|volatile|signed|unsigned|long|short)\s+
        )*
        (?:                                  # 타입 본체
            (?:struct|class|enum)\s+[A-Za-z_]\w+      # struct foo / class Bar / enum baz
            |
            Node|void|char|wchar_t|bool|int|float|double
            |size_t|ssize_t|off_t
            |termios|linux_dirent
            |_?QWORD|_?DWORD|_?WORD|_?BYTE|_?UNKNOWN
            |__int\d+|u?int\d+_t
            |unsigned\s+__int\d+                     # <-- \h 를 \s 로 수정
        )
        (?:\s+(?:const|volatile|signed|unsigned|long|short|int))*  # 뒤쪽 한정자
        (?:\s*\*+)*                              # *, **, ...
        \s*
    \)
    """,
    re.VERBOSE | re.DOTALL,
)

# 3) 포인터 체인 추출
#    a1->fd->content, fd->fd->content, a[i].b->c[2] 등
CHAIN_RE = re.compile(
    r"""
    \b
    [A-Za-z_]\w*
    (?:
        \s*(?:->|\.)\s*
        [A-Za-z_]\w*
        (?:\s*\[\s*[^]\r\n]*\s*\])?               # 선택적 인덱싱
    )+
    """,
    re.VERBOSE,
)

def strip_strings(s: str) -> str:
    return STRING_RE.sub(' ', s)

def strip_casts(s: str, max_iter: int = 6) -> str:
    cur = s
    for _ in range(max_iter):
        new = CAST_RE.sub(' ', cur)
        if new == cur:
            break
        cur = new
    return cur

def _try_parse_outer(line: str) -> bool:
    # This is unnecessary lol
    if line.startswith("void"):
        ld(f"Found function declaration: {line}")
        return True
    elif line.startswith("{"):
        ld("Found function body start")
        return True
    elif line.startswith("}"):
        ld("Found function body end")
        return True
    elif line.startswith("  "): # The inner block
        # ld(f"Found inner block: {line}")
        return False
    elif line.strip() == "":
        ld("Found empty line")
        return True
    else:
        raise RuntimeError(f"Unknown line format: {line}")

def find_pointer_chains(line: str):
    s = strip_strings(line)
    s = strip_casts(s)
    chains = []
    for m in CHAIN_RE.finditer(s):
        end = m.end()
        j = end
        while j < len(s) and s[j].isspace():
            j += 1
        if j < len(s) and s[j] == '(':
            continue
        c = m.group(0)
        c = re.sub(r'\s*->\s*', '->', c)
        c = re.sub(r'\s*\.\s*', '.', c)
        c = re.sub(r'\s*\[\s*', '[', c)
        c = re.sub(r'\s*\]\s*', ']', c)
        if c not in chains:
            chains.append(c)
    return chains


def get_value_nd_chain(nd: Node, chain: str):
    if chain == "fd":
        return hex(nd.fd)
    elif chain == "bk":
        return hex(nd.bk)
    elif chain == "unk0":
        return hex(nd.unk0)
    elif chain == "content":
        return nd.content
    else:
        raise ValueError(f"Unknown chain part: {chain}")

class Block:
    def __init__(self, lines, a1, ctx):
        self.lines = lines
        self.ctx = ctx
        self.nodeptr_decls = []
        self.unkn_decls = []
        self.nodeptr_ndcls = {}
        self.translated_lines = []
        # self.next_nodes = [] # I realized that we can't calculate next nodes as lexer level, we need to go interpreter level..
        self.lexed = False

        self.nodeptr_decls.append("a1")
        self.nodeptr_ndcls["a1"] = a1

    def _try_parse_decl(self, line: str) -> bool:
        if line.startswith("Node *"):
            decl = line.split("Node *")[1].split(";")[0].strip()
            li(f"Found node pointer declaration: {decl}")
            self.nodeptr_decls.append(decl)
            self.nodeptr_ndcls[decl] = None
            return True
        elif "//" in line:
            # it means it is a declaration context, but not used in free context.
            # but we dont even have to care about this
            a = line.split(";")
            if len(a) != 2:
                raise RuntimeError(f"Unknown declaration format: {line}")
            a = a[0].split(" ")[-1]
            self.unkn_decls.append(a)
            li(f"Found unknown declaration: {a}")
            return True
        return False

    def _find_node_with_label(self, label: str):
        for v in self.ctx.values():
            if v.label == label:
                return v
        return None

    def parse_pointer_chain(self, pointer_chain: str):
        chains = pointer_chain.split("->")
        
        primitive = chains[0]

        if self.nodeptr_ndcls.get(primitive) is None and self._find_node_with_label(primitive) is None:
            raise RuntimeError(f"Corrupted pointer chain: {pointer_chain} (primitive not defined)")

        nd = self._find_node_with_label(primitive) if self.nodeptr_ndcls.get(primitive) is None else self.nodeptr_ndcls[primitive]
        last_chain = None
        for i, chain in enumerate(chains[1:]):
            if i == len(chains) - 2:
                if chain not in ['fd', 'bk', 'unk0', 'content']:
                    raise RuntimeError(f"Corrupted pointer chain: {pointer_chain} (last chain not defined in correct scope)")
                last_chain = chain
                break
            if chain == 'fd':
                nd = self.ctx[nd.fd]
            else:
                raise RuntimeError(f"Corrupted pointer chain: {pointer_chain} (unknown chain type {chain})")
        li(f"Parsed {pointer_chain} as {nd.label}->{last_chain}")
        return nd, last_chain
    
    def _translate_line(self, line: str) -> str:

        chains = find_pointer_chains(line)
        translated = "" + line
        for chain in chains:
            nd, last_chain = self.parse_pointer_chain(chain)
            nd_chain = get_value_nd_chain(nd, last_chain)
            nd_chain = hex(nd_chain) if isinstance(nd_chain, int) else nd_chain
            translated = translated.replace(chain, f"{nd.label}->{last_chain}")

        li(f"Translated line: {line} -> {translated}")

        return translated

    def _assign_glovar(self, n, lc, assignment):
        if lc == 'fd':
            self.ctx[n.ea].fd = assignment
        elif lc == 'bk':
            self.ctx[n.ea].bk = assignment
        elif lc == 'unk0':
            self.ctx[n.ea].unk0 = assignment
        elif lc == 'content':
            self.ctx[n.ea].content = assignment
        else:
            raise ValueError(f"Unknown left-hand side in global variable assignment: {lc}")

    def _try_parse_eql(self, line: str) -> bool:
        tst = line.split(" = ")
        if len(tst) > 2:
            raise RuntimeError(f"Unknown assignment format: {line}") # Wtf?
        if len(tst) == 1: # if there's no ' = ', it means it's not a valid assignment
            return False
        left, right = tst
        
        if left not in self.nodeptr_decls:
            li(f"Found non-node-pointer left-hand side in assignment: {left}")
            return True
        
        li(f"Found assignment: {left} = {right}")

        # if it is Node* assignment, 
        right = find_pointer_chains(right)
        if len(right) != 1:
            raise RuntimeError(f"Unknown right-hand side in assignment: {right} (not single pointer chain)")
        right = right[0]
        nd, last_chain = self.parse_pointer_chain(right)
        if last_chain != 'fd':
            raise RuntimeError(f"Unknown right-hand side in assignment: {right} (not fd)")
        assign = self.ctx[nd.fd]
        li(f"  Parsed right-hand side: {assign.label}")
        self.nodeptr_ndcls[left] = assign
        return True

    def lex(self):
        for line in self.lines:

            if _try_parse_outer(line):
                self.translated_lines.append(line)
                continue
            # Get spaces in start
            space_count = 0
            while space_count < len(line) and line[space_count] == ' ':
                space_count += 1
            inner = line.strip()

            # if it is inner block, let's first translate line
            translated = self._translate_line(inner)
            translated = " " * space_count + translated
            self.translated_lines.append(translated) # I understand, we can't directly assign inner to translated

            # Check if it is kind of declaration
            if self._try_parse_decl(inner):
                continue
            
            # Check if it is {a} = {b} assignment
            if self._try_parse_eql(inner):
                continue

            lw(f"Unknown inner line format: {inner}")

        self.lexed = True

    def translated(self):
        if not self.lexed:
            raise RuntimeError("Block not lexed yet")
        return "\n".join(self.translated_lines)