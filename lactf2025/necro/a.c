#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define SIZE 49
#define N 7

char n_label[SIZE] = {
    1, 1, 0, 0, 0, 0, 0,
    0, 1, 0, 2, 0, 0, 0, 0,
    0, 3, 1, 0, 0, 0, 0, 0,
    1, 0, 1, 0, 0, 0, 0, 0,
    1, 3, 0, 0, 0, 1, 0, 1,
    0, 1, 0, 0, 0, 2, 2, 2,
    0, 0
};

int locked[SIZE] = {
    /* indices 0~7 */  0, 0, 0, 0, 0, 0, 0, 0,
    /* index 8 */       1,
    /* indices 9~15 */  0, 0, 0, 0, 0, 0, 0,
    /* index 16 */      0,
    /* index 17 */      1,
    /* indices 18~22 */ 0, 0, 0, 0, 0,
    /* index 23 */      1,
    /* index 24 */      0,
    /* index 25 */      1,
    /* indices 26~30 */ 0, 0, 0, 0, 0,
    /* index 31 */      1,
    /* indices 32~39 */ 0, 0, 0, 0, 0, 0, 0, 0,
    /* indices 40~44 */ 0, 0, 0, 0, 1,
    /* indices 45~48 */ 0, 1, 0, 1
};

static char seen[SIZE];
static char cnts[4];

bool dfs_component(int x, int y, char *state, char *seen, char *cnts, bool *open) {
    int idx = y * N + x;
    seen[idx] = 1;
    
    if ( n_label[idx] ) {
        cnts[n_label[idx]]++;
        if (cnts[n_label[idx]] > 2)
            return false;
    }
    
    int dx[4] = {0, 0, -1, 1};
    int dy[4] = {-1, 1, 0, 0};
    char color = state[idx];
    
    for (int i = 0; i < 4; i++) {
        int xx = x + dx[i];
        int yy = y + dy[i];
        if (xx < 0 || xx >= N || yy < 0 || yy >= N)
            continue;
        int nidx = yy * N + xx;
        if (!seen[nidx]) {
            if (state[nidx] == -1) {
                *open = true;
            } else if (state[nidx] == color) {
                if (!dfs_component(xx, yy, state, seen, cnts, open))
                    return false;
            }
        }
    }
    return true;
}

bool check_partial_state(char *state) {
    memset(seen, 0, sizeof(seen));
    for (int y = 0; y < N; y++) {
        for (int x = 0; x < N; x++) {
            int idx = y * N + x;
            if (state[idx] == -1)
                continue;
            if (seen[idx])
                continue;
            char local_cnts[4] = {0,0,0,0};
            bool open = false;
            if (!dfs_component(x, y, state, seen, local_cnts, &open))
                return false;
            if (!open) {  
                for (int i = 1; i < 4; i++) {
                    if (local_cnts[i] == 1)
                        return false;
                }
            }
        }
    }
    return true;
}

bool full_check(char *state) {
    return check_partial_state(state);
}

bool solve(char *state, int idx) {
    if (idx == SIZE) {
        return full_check(state);
    }
    if (locked[idx]) {
        state[idx] = 1;
        return solve(state, idx + 1);
    }
    for (int v = 0; v < 2; v++) {
        state[idx] = v;
        if (check_partial_state(state)) {
            if (solve(state, idx + 1))
                return true;
        }
        state[idx] = -1;
    }
    return false;
}

int main(void) {
    char state[SIZE];
    for (int i = 0; i < SIZE; i++) {
        state[i] = -1;
    }
    
    if (solve(state, 0)) {
        printf("===================================\n");
        printf("WINNER found!\n");
        printf("===================================\n");
        for (int y = 0; y < N; y++) {
            for (int x = 0; x < N; x++) {
                int idx = y * N + x;
                printf("%c", state[idx] ? '#' : '_');
            }
            printf("\n");
        }
        FILE *fp = fopen("WINNER.txt", "w");
        if (fp) {
            for (int y = 0; y < N; y++) {
                for (int x = 0; x < N; x++) {
                    int idx = y * N + x;
                    fprintf(fp, "%c", state[idx] ? '#' : '_');
                }
                fprintf(fp, "\n");
            }
            fclose(fp);
        }
        return 0;
    } else {
        printf("No solution found.\n");
        return 1;
    }
}
