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