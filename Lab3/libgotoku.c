#include <stdio.h>
#include <stdbool.h>
#include <dlfcn.h>
#include "libgotoku.h"

#define SIZE 9

static gotoku_t *_board = NULL;
bool solve_sudoku(gotoku_t *board);

void gop_show() {
    if (_board == NULL) {
        static gotoku_t *(*orig_game_load)(const char *) = NULL;
        if (!orig_game_load) {
            orig_game_load = dlsym(RTLD_NEXT, "game_load");
        }
        
        const char *path = "/gotoku.txt";
        _board = orig_game_load(path);
    }

    if (_board == NULL) {
        printf("Error: board not initialized\n");
        return;
    }

    printf("%d %d\n", _board->x, _board->y);
    
    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            printf("%d%c", _board->board[i][j], (j != 8 ? ' ' : '\n'));
        }
    }

    solve_sudoku(_board);
}


bool is_valid_move(gotoku_t *board, int row, int col, int num) {

    for (int c = 0; c < SIZE; c++) if (board->board[row][c] == num) return false;
    for (int r = 0; r < SIZE; r++) if (board->board[r][col] == num) return false;
        
    int start_row = (row / 3) * 3;
    int start_col = (col / 3) * 3;
    for (int r = start_row; r < start_row + 3; r++) {
        for (int c = start_col; c < start_col + 3; c++) {
            if (board->board[r][c] == num) return false;
        }
    }

    return true;
}

bool solve_sudoku(gotoku_t *board) {
    for (int row = 0; row < SIZE; row++) {
        for (int col = 0; col < SIZE; col++) {
            if (board->board[row][col] == 0) {
                for (int num = 1; num <= SIZE; num++) {
                    if (is_valid_move(board, row, col, num)) {
                        board->board[row][col] = num;
                        
                        if (solve_sudoku(board)) return true;
                        
                        board->board[row][col] = 0;
                    }
                }
                return false;
            }
        }
    }
    return true;
}

void gop_random() {}

#define GAME_OP(n)   void gop_##n() { gop_random(); }
#include "gops.c"
#undef GAME_OP