echo "Testing ex1:"
echo ""
LD_PRELOAD=./libzpoline.so.1 ./ex1
echo ""
echo ""

echo "Testing ex2-1:"
echo ""
LD_PRELOAD=./libzpoline.so.2 /usr/bin/echo 'uphw{7h15_15_4_51mpl3_fl46_fr0m_200l4b}'
echo ""
echo ""

echo "Testing ex2-2:"
echo ""
LD_PRELOAD=./libzpoline.so.2 cat ex2-2.txt
echo ""
echo ""

echo "Testing ex3:"
echo ""
LD_PRELOAD=./libzpoline.so LIBZPHOOK=./libex3hook.so ./ex3
echo ""
echo ""
