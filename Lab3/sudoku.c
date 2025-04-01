#include <stdio.h>
#include <stdlib.h>

#define SIZE 9

void print_grid(int grid[SIZE][SIZE]) {
    for(int i = 0; i < SIZE; i++) {
        for(int j = 0; j < SIZE; j++)
            printf("%d ", grid[i][j]);

        printf("\n");
    }
}

int is_valid(int grid[SIZE][SIZE], int row, int col, int num) {
    for (int i = 0; i < SIZE; i++)
        if (grid[row][i] == num || grid[i][col] == num) return 0;
    
        int start_row = (row / 3) * 3;
        int start_col = (col / 3) * 3;

        for(int i = 0; i < 3; i++) {
            for(int j = 0; j < 3; j++) 
                if(grid[start_row + i][start_col + j] == num) return 0;
        }
    
    return 1;
}

int solve_sudoku(int grid[SIZE][SIZE]) {
    for(int row = 0; row < SIZE; row++) {
        for(int col = 0; col < SIZE; col++) {
            if(grid[row][col] == 0) {
                for(int num = 1; num <= SIZE; num++) {
                    if(is_valid(grid, row, col, num)) {
                        grid[row][col] = num;
                        if(solve_sudoku(grid)) return 1;
                        grid[row][col] = 0;
                    }
                }

                return 0;
            }
        }
    }

    return 1;
}

int load_puzzle(const char *filename, int grid[SIZE][SIZE]) {
    FILE *file = fopen(filename, "r");
    if(!file) return 0;

    for(int i = 0; i < SIZE; i++) {
        for(int j = 0; j < SIZE; j++)
            fscanf(file, "%d", &grid[i][j]);
    }

    fclose(file);

    return 1;
}

int main() {
    int grid[SIZE][SIZE];

    int err = load_puzzle("/gotoku.txt", grid);
    if(!err) {
        printf("Error loading file");
        exit(1);
    }

    int solved = solve_sudoku(grid);
    if(solved == 0) printf("Not solvable\n");
    else print_grid(grid);

    return 0;
}