# tongxin_jiami
//编译
gcc client.c -o client1 -lssl -lcrypto -lpthread
gcc server.c -o client1 -lssl -lcrypto -lpthread
//运行示例
./client1 192.168.77.37 8888
./server 8888
