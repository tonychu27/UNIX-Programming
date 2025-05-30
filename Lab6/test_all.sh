#!/bin/bash

for i in {1..4}; do
    echo -e "Testing Challenge #$i:\n"
    python3 solve_$i.py
    echo ""
done