import gdb
import shutil
import os
import subprocess

class breakpoint(gdb.Breakpoint):
    def __init__(self, location, function):
        super(breakpoint, self).__init__("*"+ hex(location), gdb.BP_BREAKPOINT)
        self.function = function
        self.silent = True
        self.thread = 1

    def stop(self):
        if self.function():
            return True
        return False

def get_base_address():
    mappings = gdb.execute("info proc mappings", to_string=True)
    for line in mappings.splitlines():
        if gdb.current_progspace().filename in line:
            parts = line.split()
            base_address = int(parts[0], 16)
            return base_address

def read_string_from_address(address):
    result = []
    segment = b'a'
    while len(segment):
        memory = gdb.inferiors()[0].read_memory(address, 1)
        segment = memory.tobytes().split(b'\x00')[0]
        result.append(segment)

        address += 1

    return b''.join(result)

# transform to files
class DIR:
    malloc_stage = 0x0000000000038F9 # when mov [r12+18h], rax
    lseek_init = 0x00000000000385A
    check_valid_dir = 0x000000000004746 # when movzx eax, byte ptr [rax]

    @staticmethod
    def load(path, data):
        stack = b''
        order = []

        while len(data) > 0:
            item = data[:1]
            data = data[1:]

            if item in [b'/', b'\x00']:
                name = stack.decode()
                order.append(name)
                stack = b''

                if item == b'/':
                    if data[:1] == b'/': # if is just file
                        with open(f"{path}/{name}", 'wb') as f:
                            f.write(data[1:])
                        return b'', order

                    os.mkdir(f"{path}/{name}")
                elif item == b'\x00':
                    if len(name) == 0:
                        return data, order[:-1]

                    length = int.from_bytes(data[:8], 'little')
                    data = data[8:]
                    with open(f"{path}/{name}", 'wb') as f:
                        f.write(data[:length])
                        data = data[length:]
            else:
                stack += item

    @staticmethod
    def transform_from_data(data):
        path = "res"

        if os.path.isdir(path):
            shutil.rmtree(path)
        os.mkdir(path)

        data, order = DIR.load(path, data)

        gdb.execute('starti `echo "res">tmp` <tmp', to_string=True)
        
        def new_dir():
            nonlocal data, order
            addr = int(str(gdb.parse_and_eval("$rax")))
            string = read_string_from_address(addr).decode()
            data, order = DIR.load(f"{path}/{string}", data)
        
        def change_data_by_order():
            nonlocal order

            addr = int(str(gdb.parse_and_eval("$rax")))
            origin = read_string_from_address(addr).decode()

            if len(origin) == 32:
                nxt = order[0]
                order = order[1:]

                for i in range(len(nxt)):
                    gdb.execute(f"set *(char*){addr + i} = {ord(nxt[i])}")
                    
        base = get_base_address()
        breakpoint(base + DIR.malloc_stage, new_dir)
        breakpoint(base + DIR.check_valid_dir, change_data_by_order)
        breakpoint(base + DIR.lseek_init, lambda: True)

        gdb.execute("continue", to_string=False)
        
        shutil.rmtree('/tmp/.zrq')


with open('./quiz.zrq.0', 'rb') as f:
    dir_data = f.read()

DIR.transform_from_data(dir_data)

os.chdir('res')
exec(open('flag.py').read())

gdb.execute("quit", to_string=True)