#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <netinet/in.h>
#include <sys/time.h>

#define BUFFER_SIZE 1024
#define CHUNK_SIZE 500
#define PAYLOAD_SIZE 492
#define AES_KEY_SIZE 16

#pragma pack(push, 1)
typedef struct {
    uint16_t length;
    uint16_t checksum;
    unsigned char data[PAYLOAD_SIZE];
} Chunk;
#pragma pack(pop)

int sock;
EVP_CIPHER_CTX *encrypt_ctx;
unsigned char iv[EVP_MAX_IV_LENGTH];

// 可靠发送函数
int reliable_send(int sockfd, const void *buf, size_t len) {
    size_t total = 0;
    while(total < len) {
        ssize_t sent = send(sockfd, (char*)buf + total, len - total, 0);
        if(sent <= 0) return -1;
        total += sent;
    }
    return total;
}

void init_crypto() {
    // 使用固定16字节密钥
    unsigned char key[AES_KEY_SIZE] = {
        'T','h','i','s','I','s','A','S',
        'e','c','r','e','t','K','e','y'
    };
    
    // 生成随机IV
    FILE* urandom = fopen("/dev/urandom", "rb");
    fread(iv, 1, EVP_CIPHER_iv_length(EVP_aes_128_cbc()), urandom);
    fclose(urandom);

    // 初始化加密上下文
    //encrypt_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(encrypt_ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(encrypt_ctx, 0);

    printf("客户端IV: ");
    for(int i=0; i<16; i++){
        printf("%02X ", iv[i]);
    }
    printf("\n");
}

void encrypt_chunk(Chunk* chunk) {
    int outlen;
    //unsigned char ivec[EVP_MAX_IV_LENGTH];
    //memcpy(ivec, iv, EVP_MAX_IV_LENGTH);
    
    //EVP_EncryptInit_ex(encrypt_ctx, NULL, NULL, NULL, ivec);
    if(!EVP_EncryptUpdate(encrypt_ctx, 
                         (unsigned char*)chunk, &outlen,
                         (unsigned char*)chunk, sizeof(Chunk))) {
        fprintf(stderr, "加密失败\n");
        exit(EXIT_FAILURE);
    }
}

void* recv_handler(void* arg) {
    unsigned char buffer[CHUNK_SIZE];
    while(1) {
        ssize_t len = recv(sock, buffer, CHUNK_SIZE, 0);
        if(len <= 0) {
            printf("服务器断开连接\n");
            break;
        }
        printf("收到加密块 (%zd 字节)\n", len);
    }
    close(sock);
    pthread_exit(NULL);
}

void send_message(int sock, const char* msg) {
    Chunk real_chunk, fake_chunk;
    int msg_len = strlen(msg);
    int pos = 0;

    while(pos < msg_len) {
        memset(&real_chunk, 0, sizeof(Chunk));
        int chunk_len = (msg_len - pos) > PAYLOAD_SIZE ? 
                       PAYLOAD_SIZE : (msg_len - pos);
        
        real_chunk.length = htons(chunk_len);
        memcpy(real_chunk.data, msg + pos, chunk_len);
        
        if(chunk_len < 0 || chunk_len > PAYLOAD_SIZE) {
            fprintf(stderr, "非法分片长度: %d\n", chunk_len);
            exit(EXIT_FAILURE);
        }

        // 填充随机数据
        if(chunk_len < PAYLOAD_SIZE) {
            FILE* urandom = fopen("/dev/urandom", "rb");
            if(!urandom) {
                perror("打开随机设备失败");
                exit(EXIT_FAILURE);
            }
            fread(real_chunk.data + chunk_len, 1, 
                 PAYLOAD_SIZE - chunk_len, urandom);
            fclose(urandom);
        }
        
        // 计算校验和
        uint16_t checksum = 0;
        for(int i=0; i<chunk_len; i++)
            checksum += real_chunk.data[i];
        real_chunk.checksum = htons(checksum);
        
        // 加密并发送
        encrypt_chunk(&real_chunk);
        if(reliable_send(sock, &real_chunk, sizeof(Chunk)) < 0) {
            perror("发送失败");
            exit(EXIT_FAILURE);
        }
        pos += chunk_len;

        // 插入伪数据包（25%概率）
        if(rand() % 4 == 0) { 
            FILE* urandom = fopen("/dev/urandom", "rb");
            if(!urandom) {
                perror("打开随机设备失败");
                exit(EXIT_FAILURE);
            }
            fread(&fake_chunk, 1, sizeof(Chunk), urandom);
            fake_chunk.checksum = htons(0xFFFF); // 伪包标记
            encrypt_chunk(&fake_chunk);
            if(reliable_send(sock, &fake_chunk, sizeof(Chunk)) < 0) {
                perror("发送伪包失败");
                exit(EXIT_FAILURE);
            }
            fclose(urandom);
            printf("已发送伪数据包\n");
        }
    }
}

int main(int argc, char* argv[]) {
    OpenSSL_add_all_algorithms();
    srand(time(NULL));

    if(argc != 3) {
        fprintf(stderr, "用法: %s <IP> <端口>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr;
    char *server_ip = argv[1];
    int port = atoi(argv[2]);

    // 创建socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("创建socket失败");
        exit(EXIT_FAILURE);
    }

    // 配置服务端地址
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    // IP地址转换
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("无效的IP地址格式");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // 建立连接
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        perror("连接失败");
        close(sock);
        exit(EXIT_FAILURE);
    }
    printf("已连接到 %s:%d\n", server_ip, port);

    // 初始化加密并发送IV
    init_crypto();
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    if(reliable_send(sock, iv, iv_len) != iv_len) {
        perror("发送IV失败");
        close(sock);
        exit(EXIT_FAILURE);
    }
    printf("已发送IV (%d bytes)\n", iv_len);

    // 创建接收线程
    pthread_t recv_thread;
    pthread_create(&recv_thread, NULL, recv_handler, NULL);

    // 主线程处理输入
    char message[BUFFER_SIZE];
    while(1) {
        fgets(message, BUFFER_SIZE, stdin);
        if(strcmp(message, "exit\n") == 0) break;
        send_message(sock, message);
    }

    EVP_CIPHER_CTX_free(encrypt_ctx);
    close(sock);
    return 0;
}
