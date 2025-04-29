make clean
make

echo "Testing ex1:"
LD_PRELOAD=./libzpoline.so.1 ./ex1
echo ""
echo ""

echo "Testing ex2-1:"
LD_PRELOAD=./libzpoline.so.2 /usr/bin/echo 'uphw{7h15_15_4_51mpl3_fl46_fr0m_200l4b}'
echo ""
echo ""

echo "Testing ex2-2:"
LD_PRELOAD=./libzpoline.so.2 cat ex2-2.txt
echo ""
echo ""

echo "Testing ex3:"
LD_PRELOAD=./libzpoline.so LIBZPHOOK=./libex3hook.so ./ex3
echo ""
echo ""

echo "Testing ex4-1:"
LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so touch main.c
echo ""
echo ""

echo "Testing ex4-2:"
LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so cat /etc/hosts
echo ""
echo ""

echo "Testing ex5:"
LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so wget http://www.google.com -q -t 1
echo ""
echo ""

echo "Testing ex6:"
LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so python3 -c 'import os; os.system("wget http://www.google.com -q -t 1")'
sleep 10
echo ""
echo ""

echo "Testing Hidden 1-1:"
LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so cp ex3 '[vsyscall]'
echo ""
echo ""

echo "Testing Hidden 1-2:"
LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so ./'[vsyscall]'
echo ""
echo ""

echo "Testing Hidden 3:"
LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so bash -c 'curl -s file:///etc/hosts'
sleep 10
echo ""
echo ""

echo "Testing Hidden 4:"
LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so python3 -c 'import os; os.system("python3 -c '\''import os; os.system(\"id\")'\''")'
sleep 18
echo ""
echo ""

echo "Testing Hidden 2:"

SESSION_NAME="zpoline_test"
SOCKET_PATH="/tmp/hidden3.sock"

rm -f "$SOCKET_PATH"

tmux new-session -d -s "$SESSION_NAME"
tmux send-keys -t "$SESSION_NAME" "LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so nc -lkU $SOCKET_PATH" C-m
tmux split-window -h -t "$SESSION_NAME"
tmux send-keys -t "$SESSION_NAME":0.1 "sleep 1 && LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so nc -U $SOCKET_PATH" C-m
tmux send-keys -t "$SESSION_NAME":0.1 "<type some random text here...>" C-m
tmux attach -t "$SESSION_NAME"

rm -rf index*