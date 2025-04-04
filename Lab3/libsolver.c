#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>

#include "libgotoku.h"
#include "offset.h"

#define SIZE 9
#define MAIN_OFFSET 0x16c89

void *main_address;

void modify_entry(void *handle, char *method, int got_cnt) {

    void (*gop)(void) = (void (*)(void))dlsym(handle, method);
    void *got = main_address - MAIN_OFFSET + GOT_OFFSET[got_cnt];

    uintptr_t page_start = (uintptr_t)got & ~(getpagesize() - 1);

    /*** Make GOT Table Writeable ***/
    if (mprotect((void *)page_start, getpagesize(), PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect");
        exit(EXIT_FAILURE);
    }

    void **got_entry = (void **)got;
    *got_entry = (void *)gop;

    /*** Restore GOT Table to Read Only ***/
    if (mprotect((void *)page_start, getpagesize(), PROT_READ) != 0) {
        perror("mprotect restore");
        exit(EXIT_FAILURE);
    }
}

void complete_sudoku(int *board, int *solvedBoard, void *handle) {
    int got_cnt = 0;

    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            int index = i * SIZE + j;

            if (board[index] != solvedBoard[index]) {
                switch (solvedBoard[index]) {
                    case 1: modify_entry(handle, "gop_fill_1", got_cnt++); break;
                    case 2: modify_entry(handle, "gop_fill_2", got_cnt++); break;
                    case 3: modify_entry(handle, "gop_fill_3", got_cnt++); break;
                    case 4: modify_entry(handle, "gop_fill_4", got_cnt++); break;
                    case 5: modify_entry(handle, "gop_fill_5", got_cnt++); break;
                    case 6: modify_entry(handle, "gop_fill_6", got_cnt++); break;
                    case 7: modify_entry(handle, "gop_fill_7", got_cnt++); break;
                    case 8: modify_entry(handle, "gop_fill_8", got_cnt++); break;
                    case 9: modify_entry(handle, "gop_fill_9", got_cnt++); break;
                }
            }

            modify_entry(handle, "gop_right", got_cnt++);
        }

        for (int i = 0; i < SIZE; i++) modify_entry(handle, "gop_left", got_cnt++);

        modify_entry(handle, "gop_down", got_cnt++);
    }
}

bool is_valid(int *board, int index) {
    int ans = board[index];
    int row = index / SIZE;
    int col = index % SIZE;
    
    for (int i = 0; i < SIZE; i++)
        if ((row * SIZE + i != index) && board[row * SIZE + i] == ans) return false;
        
    for (int i = 0; i < SIZE; i++)
        if ((i * SIZE + col != index) && board[i * SIZE + col] == ans) return false;
        
    int startRow = (row / 3) * 3;
    int startCol = (col / 3) * 3;
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            int blkIndex = (startRow + i) * SIZE + (startCol + j);
            if (blkIndex != index && board[blkIndex] == ans) return false;
        }
    }

    return true;
}

bool solve_sudoku(int *board, int index) {
    if (index >= SIZE * SIZE) return true;
    if (board[index] != 0) return solve_sudoku(board, index + 1);
    

    for (int num = 1; num <= SIZE; num++) {
        board[index] = num;
        if (is_valid(board, index) && solve_sudoku(board, index + 1)) return true;
    }

    board[index] = 0;
    return false;
}

int *get_board(int *board, int index) {
    solve_sudoku(board, 0);

    return board;
}

int game_init() {
    gotoku_t *board = NULL;
    gotoku_t _board;
    
    main_address = game_get_ptr();

    printf("UP113_GOT_PUZZLE_CHALLENGE\n");
    printf("SOLVER: _main = %p\n", main_address);
    
    const char *filename = "/gotoku.txt";
    board = game_load(filename);
    _board = *board;
    
    int *solvedBoard = get_board((int *)_board.board, 0);
    
    const char *library = "libgotoku.so";
    void *handle = dlopen(library, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    dlerror();

    complete_sudoku((int *)board->board, solvedBoard, handle);

    return 0;
}