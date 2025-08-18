cat build.sh
tigress src/main.c --out=build/main.tigress.c \
    --Transform=Virtualize \
    --VirtualizeDispatch=direct \
    --Functions=create_linear_sbox,get_urandom_byte,KeyExpansion,AddRoundKey,SubBytes,ShiftRows,MixColumns,xtime,Cipher,main
gcc -o build/main build/main.tigress.c -march=native -Wall -Wextra -std=c11
strip build/main
./build/main < flag.txt > build/output
