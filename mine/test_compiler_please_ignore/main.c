/*
 * BSD 3-Clause License
 * 
 * Copyright (c) 2025, Wane
 * All rights reserved.
 * 
 * Author: Wane
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define Nb 4
#define Nk 4
#define Nr 10

typedef uint8_t state_t[4][4];

uint8_t sbox[256];

const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

uint8_t round_key[176];

#define getSBoxValue(num) (sbox[(num)])
void create_linear_sbox() {
    // Why do we do this?
    // Tigress will compile this sbox stealthily, so we need to declare temporary array for storing sbox.
    // The sbox is a linear transformation, so we can oracle attack aes.
    uint8_t tmp[256] = {
        0, 33, 93, 124, 84, 117, 9, 40, 63, 30, 98, 67, 107, 74, 54, 23, 82, 115, 15, 46, 6, 39, 91, 122, 109, 76, 48, 17, 57, 24, 100, 69, 119, 86, 42, 11, 35, 2, 126, 95, 72, 105, 21, 52, 28, 61, 65, 96, 37, 4, 120, 89, 113, 80, 44, 13, 26, 59, 71, 102, 78, 111, 19, 50, 172, 141, 241, 208, 248, 217, 165, 132, 147, 178, 206, 239, 199, 230, 154, 187, 254, 223, 163, 130, 170, 139, 247, 214, 193, 224, 156, 189, 149, 180, 200, 233, 219, 250, 134, 167, 143, 174, 210, 243, 228, 197, 185, 152, 176, 145, 237, 204, 137, 168, 212, 245, 221, 252, 128, 161, 182, 151, 235, 202, 226, 195, 191, 158, 253, 220, 160, 129, 169, 136, 244, 213, 194, 227, 159, 190, 150, 183, 203, 234, 175, 142, 242, 211, 251, 218, 166, 135, 144, 177, 205, 236, 196, 229, 153, 184, 138, 171, 215, 246, 222, 255, 131, 162, 181, 148, 232, 201, 225, 192, 188, 157, 216, 249, 133, 164, 140, 173, 209, 240, 231, 198, 186, 155, 179, 146, 238, 207, 81, 112, 12, 45, 5, 36, 88, 121, 110, 79, 51, 18, 58, 27, 103, 70, 3, 34, 94, 127, 87, 118, 10, 43, 60, 29, 97, 64, 104, 73, 53, 20, 38, 7, 123, 90, 114, 83, 47, 14, 25, 56, 68, 101, 77, 108, 16, 49, 116, 85, 41, 8, 32, 1, 125, 92, 75, 106, 22, 55, 31, 62, 66, 99
    };
    for (int i = 0; i < 256; ++i) {
        sbox[i] = tmp[i];
    }
}

static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  
  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

static void ShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left  
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left  
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

static void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

static void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without MixColumns()
  for (round = 1; ; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    if (round == Nr) {
      break;
    }
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  // Add round key to last round
  AddRoundKey(Nr, state, RoundKey);
}

void get_urandom_byte(uint8_t* buf, size_t len) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        return;
    }
    if (fread(buf, len, 1, fp) != 1) {
        fclose(fp);
        return;
    }
    fclose(fp);
}

#define BUFFER_SIZE 64
#define TOTAL_SIZE 80
#define INPUT_OFFSET 16

int main() {
    create_linear_sbox();

    uint8_t key[16];
    get_urandom_byte(key, 16);
    KeyExpansion(round_key, key);

    uint8_t text[TOTAL_SIZE];
    if (fread(text + INPUT_OFFSET, 1, BUFFER_SIZE, stdin) != BUFFER_SIZE) {
        return 1;
    }

    get_urandom_byte(text, INPUT_OFFSET);
    if (fwrite(text, 1, INPUT_OFFSET, stdout) != INPUT_OFFSET) {
        return 1;
    }

    for (int i = 0; i < TOTAL_SIZE; i += 16) {
        Cipher((state_t*)(text + i), round_key);
    }

    if (fwrite(text, 1, TOTAL_SIZE, stdout) != TOTAL_SIZE) {
        return 1;
    }

    return 0;
}
