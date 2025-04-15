#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <netinet/in.h>

#define AES_BLOCK_SIZE 16
#define MAX_CONN 5
#define CHUNK_SIZE 500
#define PAYLOAD_SIZE 496
#define AES_KEY_SIZE 16
#define BUFFER_SIZE 4096

#pragma pack(push, 1)
typedef struct {
    uint16_t length;
    uint16_t checksum;
    unsigned char data[PAYLOAD_SIZE];
} Chunk;
#pragma pack(pop)

typedef struct {
    int client_fd;
    unsigned char iv[EVP_MAX_IV_LENGTH];
} ClientContext;

const unsigned char encryption_key[AES_KEY_SIZE] = {
    'T','h','i','s','I','s','A','S',
    'e','c','r','e','t','K','e','y'
};

// 可靠接收函数
int reliable_recv(int sockfd, void *buf, size_t len) {
    size_t total = 0;
    while(total < len) {
        ssize_t received = recv(sockfd, (char*)buf + total, len - total, 0);
        if(received <= 0) return -1;
        total += received;
    }
    return total;
}

void* client_handler(void *arg) {
    ClientContext *ctx = (ClientContext*)arg;
    EVP_CIPHER_CTX *decrypt_ctx = EVP_CIPHER_CTX_new();
    
    // 初始化解密
    if(1 != EVP_DecryptInit_ex(decrypt_ctx, EVP_aes_128_cbc(), 
                              NULL, encryption_key, ctx->iv)) {
        fprintf(stderr, "解密初始化失败\n");
        close(ctx->client_fd);
        free(ctx);
        pthread_exit(NULL);
    }
    EVP_CIPHER_CTX_set_padding(decrypt_ctx, 0);

    Chunk chunk;
    char reassembly_buffer[BUFFER_SIZE] = {0};
    int buffer_pos = 0;

    while(1) {
        if(reliable_recv(ctx->client_fd, &chunk, sizeof(Chunk)) < 0) {
            printf("客户端断开连接\n");
            break;
        }

        int out_len;
        unsigned char decrypted[sizeof(Chunk)+AES_BLOCK_SIZE] = {0};
        
        // 解密时增加错误检查
        if(1 != EVP_DecryptUpdate(decrypt_ctx, decrypted, &out_len, 
                                (unsigned char*)&chunk, sizeof(Chunk))) {
            fprintf(stderr, "解密失败\n");
            break;
        }

        printf("[调试] 原始解密数据长度: %d bytes\n", out_len);
         if(out_len < sizeof(uint16_t)*2) {
            fprintf(stderr, "无效解密数据长度\n");
            continue;
        }

        // 严格解析解密后的数据
        if(out_len < sizeof(uint16_t)*2) {
            fprintf(stderr, "无效解密数据长度\n");
            continue;
        }

        // 正确提取长度和校验和
        uint16_t payload_len, received_checksum;
        memcpy(&payload_len, decrypted, sizeof(uint16_t));
        memcpy(&received_checksum, decrypted + sizeof(uint16_t), sizeof(uint16_t));
        payload_len = ntohs(payload_len);
        received_checksum = ntohs(received_checksum);

        if (received_checksum == 0xFFFF) {
            printf("检测到伪数据包，已跳过\n");
            continue; 
        }
        
        printf("[调试] 解析得到载荷长度: %d (原始值: 0x%04X)\n", payload_len, ntohs(payload_len));

        // 验证载荷长度
        if(payload_len > PAYLOAD_SIZE || payload_len <= 0) {
            fprintf(stderr, "非法载荷长度: %d (允许范围1-%d)\n", payload_len, PAYLOAD_SIZE);
            continue;
        }

        // 计算校验和
        uint16_t calc_checksum = 0;
        for(int i=0; i<payload_len; i++) {
            if(i >= out_len - sizeof(uint16_t)*2) break; // 防止越界
            calc_checksum += decrypted[sizeof(uint16_t)*2 + i];
        }

        if(received_checksum != calc_checksum) {
            fprintf(stderr, "校验和验证失败 (接收:%04X 计算:%04X)\n",
                   received_checksum, calc_checksum);
            continue;
        }

        // 安全复制有效载荷
        size_t copy_len = (payload_len < (out_len - sizeof(uint16_t)*2)) ?
                         payload_len : (out_len - sizeof(uint16_t)*2);
        
        if(buffer_pos + copy_len >= BUFFER_SIZE) {
            fprintf(stderr, "缓冲区溢出风险，重置缓冲区\n");
            buffer_pos = 0;
            continue;
        }

        memcpy(reassembly_buffer + buffer_pos, 
              decrypted + sizeof(uint16_t)*2, 
              copy_len);
        buffer_pos += copy_len;

        // 处理完整消息
        while(buffer_pos > 0) {
            char *newline = memchr(reassembly_buffer, '\n', buffer_pos);
            if(!newline) break;
            
            *newline = '\0';
            printf("解密消息: %s\n", reassembly_buffer);
            size_t remaining = buffer_pos - (newline - reassembly_buffer + 1);
            memmove(reassembly_buffer, newline + 1, remaining);
            buffer_pos = remaining;
        }
    }

    EVP_CIPHER_CTX_free(decrypt_ctx);
    close(ctx->client_fd);
    free(ctx);
    return NULL;
}

int main(int argc, char* argv[]) {
    if(argc != 2) {
        fprintf(stderr, "用法: %s <端口>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int server_fd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int port = atoi(argv[1]);

    // 创建socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket创建失败");
        exit(EXIT_FAILURE);
    }

    // 设置端口复用
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("setsockopt失败");
        exit(EXIT_FAILURE);
    }

    // 绑定地址
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        perror("绑定失败");
        exit(EXIT_FAILURE);
    }

    // 开始监听
    if (listen(server_fd, MAX_CONN) == -1) {
        perror("监听失败");
        exit(EXIT_FAILURE);
    }
    printf("服务端已启动，监听端口：%d\n", port);

    // 主循环
    while(1) {
        ClientContext *ctx = malloc(sizeof(ClientContext));
        if ((ctx->client_fd = accept(server_fd, 
                                   (struct sockaddr*)&cli_addr, 
                                   &cli_len)) == -1) {
            perror("接受连接失败");
            free(ctx);
            continue;
        }

        printf("新客户端连接: %s:%d\n", 
              inet_ntoa(cli_addr.sin_addr),
              ntohs(cli_addr.sin_port));

        // 接收IV
        int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
        if(reliable_recv(ctx->client_fd, ctx->iv, iv_len) != iv_len) {
            perror("接收IV失败");
            close(ctx->client_fd);
            free(ctx);
            continue;
        }
        printf("成功接收IV (%d bytes)\n", iv_len);
        printf("服务端IV: ");
        for(int i=0; i<16; i++) 
            printf("%02X ", ctx->iv[i]);
        printf("\n");

        // 创建线程处理客户端
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, client_handler, ctx) != 0) {
            perror("线程创建失败");
            close(ctx->client_fd);
            free(ctx);
        }
        pthread_detach(thread_id);
    }

    close(server_fd);
    return 0;
}
