#include <stdio.h>
#include <stdbool.h>
#include <dlfcn.h>
#include "libgotoku.h"

#define SIZE 9

static gotoku_t *_board = NULL;
static int cursor_x = 0, cursor_y = 0;

void move_to(int x, int y) {
    while (cursor_x > x) { gop_up(); cursor_x--; }
    while (cursor_x < x) { gop_down(); cursor_x++; }
    while (cursor_y > y) { gop_left(); cursor_y--; }
    while (cursor_y < y) { gop_right(); cursor_y++; }
}

void fill_num(int num) {
    switch(num) {
        case 0: gop_fill_0(); break;
        case 1: gop_fill_1(); break;
        case 2: gop_fill_2(); break;
        case 3: gop_fill_3(); break;
        case 4: gop_fill_4(); break;
        case 5: gop_fill_5(); break;
        case 6: gop_fill_6(); break;
        case 7: gop_fill_7(); break;
        case 8: gop_fill_8(); break;
        case 9: gop_fill_9(); break;
    }
}

bool is_valid(int row, int col, int num) {

    for(int i = 0; i < SIZE; i++) if(_board->board[row][i] == num || _board->board[i][col] == num) return false;

    int start_row = (row / 3) * 3;
    int start_col = (col / 3) * 3;

    for(int i = 0; i < 3; i++) {
        for(int j = 0; j < 3; j++) {
            if(_board->board[start_row + i][start_col + j] == num) return false;
        }
    }

    return true;
}

bool solve_sudoku() {
    for(int row = 0; row < SIZE; row++) {
        for(int col = 0; col < SIZE; col++) {
            if(_board->board[row][col] == 0) {
                for(int num = 1; num <= 9; num++) {
                    if(is_valid(row, col, num)) {
                        move_to(row, col);
                        fill_num(num);

                        if(solve_sudoku()) return true;

                        move_to(row, col);
                        fill_num(0);
                    }
                }

                return false;
            }
        }
    }
    
    return true;
}


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
}

#define GAME_OP(n)   void gop_##n() { if((n) == 1) solve_sudoku(); }
#include "gops.c"
#undef GAME_OP