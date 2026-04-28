#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <mysql.h>
#include <cjson/cJSON.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <signal.h>

#define DATA_PORT_TIMEOUT 900
#define ENABLE_DATA_PORT_TIMEOUT 1

#define SESSION_HASH_SIZE 101

#define RECV_TIMEOUT 30
#define SEND_TIMEOUT 30

#define PC_CMD_DEVONLINE_REQ 0x0005
#define PC_CMD_DEVONLINE_RET 0x0006
#define BEGINNUM 900000
#define REG_TABLE_SIZE 1024

#define HANDLE_ERROR(msg)   \
    do                      \
    {                       \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    } while (0)

typedef struct
{

    int server_port;
    int protocol_version;

    char db_host[256];
    char db_user[256];
    char db_password[256];
    char db_name[256];
    int db_port;

    char log_file[256];
    char log_level[10];

    int session_enable_timeout;
    int session_timeout_seconds;

    int data_port_enable_timeout;
    int data_port_timeout_seconds;

    int port;
    char address[256];
} Config;

Config config;

typedef struct __attribute__((packed)) DevStateRequest
{
    uint8_t serv_flag;
    uint16_t serv_cmd;
    uint32_t serv_len;
    uint8_t serv_version;
    uint32_t serv_data;
} DevStateRequest;

typedef struct __attribute__((packed)) ServHeader
{
    uint8_t serv_flag;
    uint16_t serv_cmd;
    uint32_t serv_len;
    uint8_t serv_version;
} ServHeader;

typedef struct __attribute__((packed)) REG_TABLE
{
    uint8_t ucState[REG_TABLE_SIZE];
} REG_TABLE;

typedef enum
{
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
} LogLevel;

static LogLevel current_log_level = LOG_DEBUG;

typedef struct SessionEntry
{
    char *token;
    int user_id;
    time_t created_at;
    int data_port;
    struct SessionEntry *next;
} SessionEntry;

static SessionEntry *g_session_table[SESSION_HASH_SIZE];

static pthread_mutex_t g_session_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned int hash_string(const char *str)
{
    unsigned int hash = 5381;
    int c;
    while ((c = *str++))
    {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % SESSION_HASH_SIZE;
}

int session_store(const char *token, int user_id, int data_port)
{
    if (!token)
        return -1;
    unsigned int slot = hash_string(token);

    SessionEntry *entry = (SessionEntry *)malloc(sizeof(SessionEntry));
    if (!entry)
        return -1;

    entry->token = strdup(token);
    if (!entry->token) {
    free(entry);
    return -1;
    }
    entry->user_id = user_id;
    entry->created_at = time(NULL);
    entry->data_port = data_port;
    entry->next = NULL;

    pthread_mutex_lock(&g_session_mutex);

    entry->next = g_session_table[slot];
    g_session_table[slot] = entry;
    pthread_mutex_unlock(&g_session_mutex);

    return 0;
}

static int session_lookup(const char *token)
{
    if (!token)
        return -1;

    unsigned int slot = hash_string(token);
    pthread_mutex_lock(&g_session_mutex);

    SessionEntry *cur = g_session_table[slot];
    while (cur)
    {
        if (strcmp(cur->token, token) == 0)
        {
            int uid = cur->user_id;
            pthread_mutex_unlock(&g_session_mutex);
            return uid;
        }
        cur = cur->next;
    }

    pthread_mutex_unlock(&g_session_mutex);
    return -1;
}

static const char *level_to_string(LogLevel level)
{
    switch (level)
    {
    case LOG_DEBUG:
        return "DEBUG";
    case LOG_INFO:
        return "INFO";
    case LOG_WARN:
        return "WARN";
    case LOG_ERROR:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}

static void set_log_level_by_string(const char *level_str)
{
    if (strcmp(level_str, "DEBUG") == 0)
        current_log_level = LOG_DEBUG;
    else if (strcmp(level_str, "INFO") == 0)
        current_log_level = LOG_INFO;
    else if (strcmp(level_str, "WARN") == 0)
        current_log_level = LOG_WARN;
    else if (strcmp(level_str, "ERROR") == 0)
        current_log_level = LOG_ERROR;
    else
        current_log_level = LOG_INFO;
}

void log_message(LogLevel level, const char *format, ...)
{
    if (level < current_log_level)
        return;

    FILE *fp = fopen(config.log_file, "a");
    if (!fp)
    {
        perror("打开日志文件失败");
        return;
    }

    time_t now = time(NULL);
    struct tm tbuf, *t = localtime_r(&now, &tbuf);
    if (!t)
    {
        perror("获取本地时间失败");
        fclose(fp);
        return;
    }

    fprintf(fp, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] ",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec,
            level_to_string(level));

    va_list args;
    va_start(args, format);
    vfprintf(fp, format, args);
    va_end(args);

    fprintf(fp, "\n");
    fclose(fp);
}

char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length)
{
    BIO *bio = NULL, *b64 = NULL;
    BUF_MEM *buffer_ptr = NULL;

    b64 = BIO_new(BIO_f_base64());
    if (!b64)
        return NULL;

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_new(BIO_s_mem());
    if (!bio)
    {
        BIO_free(b64);
        return NULL;
    }

    bio = BIO_push(b64, bio);

    if (BIO_write(bio, data, input_length) <= 0)
    {
        BIO_free_all(bio);
        return NULL;
    }

    if (BIO_flush(bio) != 1)
    {
        BIO_free_all(bio);
        return NULL;
    }

    BIO_get_mem_ptr(bio, &buffer_ptr);
    if (!buffer_ptr)
    {
        BIO_free_all(bio);
        return NULL;
    }

    char *encoded_data = (char *)malloc(buffer_ptr->length + 1);
    if (!encoded_data)
    {
        BIO_free_all(bio);
        return NULL;
    }

    memcpy(encoded_data, buffer_ptr->data, buffer_ptr->length);
    encoded_data[buffer_ptr->length] = '\0';

    if (output_length)
        *output_length = buffer_ptr->length;

    BIO_free_all(bio);
    return encoded_data;
}

char *generate_random_token_base64()
{
    unsigned char rand_bytes[32];
    if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1)
    {
        return NULL;
    }
    size_t encoded_len = 0;
    return base64_encode(rand_bytes, sizeof(rand_bytes), &encoded_len);
}

static void write_le16(unsigned char *buffer, uint16_t value)
{
    buffer[0] = (unsigned char)(value & 0xFF);
    buffer[1] = (unsigned char)((value >> 8) & 0xFF);
}

static void write_le32(unsigned char *buffer, uint32_t value)
{
    buffer[0] = (unsigned char)(value & 0xFF);
    buffer[1] = (unsigned char)((value >> 8) & 0xFF);
    buffer[2] = (unsigned char)((value >> 16) & 0xFF);
    buffer[3] = (unsigned char)((value >> 24) & 0xFF);
}

static uint16_t read_le16(const unsigned char *buffer)
{
    return (uint16_t)buffer[0] | ((uint16_t)buffer[1] << 8);
}

static uint32_t read_le32(const unsigned char *buffer)
{
    return (uint32_t)buffer[0] | ((uint32_t)buffer[1] << 8) | ((uint32_t)buffer[2] << 16) | ((uint32_t)buffer[3] << 24);
}

ssize_t recv_all(int sockfd, void *buffer, size_t length)
{
    size_t total = 0;
    char *buf = (char *)buffer;
    while (total < length)
    {
        ssize_t n = recv(sockfd, buf + total, length - total, 0);
        if (n <= 0)
            return n;
        total += n;
    }
    return (ssize_t)total;
}

ssize_t send_all(int sockfd, const void *buffer, size_t length)
{
    size_t total = 0;
    const char *buf = (const char *)buffer;
    while (total < length)
    {
        ssize_t n = send(sockfd, buf + total, length - total, 0);
        if (n <= 0)
            return n;
        total += n;
    }
    return (ssize_t)total;
}

typedef struct
{
    int data_port;
    int data_listen_sock;
    char login_id[256];
} DataPortInfo;

int read_file(const char *filename, char **content);
int parse_config(const char *json_str, Config *config);
void *handle_login_client(void *arg);
void *handle_data_client(void *arg);

int handle_request(
    unsigned short cmd,
    char *data,
    uint32_t data_len,
    MYSQL *conn,
    char **response,
    uint32_t *resp_len,
    const char *expected_token);

int handle_login(
    cJSON *json,
    MYSQL *conn,
    char **response,
    uint32_t *resp_len);

int handle_dclistreq(
    cJSON *json,
    MYSQL *conn,
    char **response,
    uint32_t *resp_len);

int handle_devlistreq(
    cJSON *json,
    MYSQL *conn,
    char **response,
    uint32_t *resp_len);

int handle_devstatereq(
    cJSON *json,
    MYSQL *conn,
    char **response,
    uint32_t *resp_len);

extern int close_data_port(int data_port);
int close_data_port(int data_port)
{

    log_message(LOG_INFO, "close_data_port: 关闭 data_port=%d ", data_port);
    return 0;
}

typedef struct
{
    int sockfd;
    time_t last_heartbeat;
    int is_connected;
    pthread_mutex_t mutex;
} ServerConnection;

static ServerConnection g_server_conn = {
    .sockfd = -1,
    .last_heartbeat = 0,
    .is_connected = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER};

static int is_connection_alive(int sockfd)
{
    if (sockfd < 0)
        return 0;

    fd_set read_fds;
    struct timeval timeout;

    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);
    timeout.tv_sec = 0;
    timeout.tv_usec = 1000;

    int result = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
    if (result < 0)
    {
        return 0;
    }
    else if (result > 0)
    {

        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0)
        {
            return 0;
        }
    }

    return 1;
}

int getConnection(const char *ipAddr, int port, int *socket_fd)
{
    log_message(LOG_DEBUG, "尝试建立与服务器的连接...");
    *socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*socket_fd < 0)
    {
        log_message(LOG_ERROR, "getConnection_创建套接字失败");
        return -1;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);

    if (inet_pton(AF_INET, ipAddr, &serverAddr.sin_addr) <= 0)
    {
        log_message(LOG_ERROR, "getConnection_无效的IP地址");
        close(*socket_fd);
        return -1;
    }

    int flags = fcntl(*socket_fd, F_GETFL, 0);
    fcntl(*socket_fd, F_SETFL, flags & ~O_NONBLOCK);

    int result = connect(*socket_fd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    if (result < 0)
    {
        log_message(LOG_ERROR, "getConnection_连接到服务器失败: %s", strerror(errno));
        close(*socket_fd);
        return -1;
    }

    log_message(LOG_INFO, "成功连接到服务器 %s:%d", ipAddr, port);
    return 0;
}

static int get_server_connection(int *sockfd)
{
    pthread_mutex_lock(&g_server_conn.mutex);

    if (g_server_conn.is_connected && g_server_conn.sockfd != -1)
    {
        if (is_connection_alive(g_server_conn.sockfd))
        {
            *sockfd = g_server_conn.sockfd;
            pthread_mutex_unlock(&g_server_conn.mutex);
            return 0;
        }
        else
        {

            log_message(LOG_INFO, "服务器连接已失效，重新连接");
            close(g_server_conn.sockfd);
            g_server_conn.sockfd = -1;
            g_server_conn.is_connected = 0;
        }
    }

    if (getConnection(config.address, config.port, &g_server_conn.sockfd) == 0)
    {
        g_server_conn.is_connected = 1;
        g_server_conn.last_heartbeat = time(NULL);
        *sockfd = g_server_conn.sockfd;
        pthread_mutex_unlock(&g_server_conn.mutex);
        log_message(LOG_DEBUG, "创建新的服务器连接: %s:%d", config.address, config.port);
        return 0;
    }
    else
    {

        g_server_conn.sockfd = -1;
        g_server_conn.is_connected = 0;
        pthread_mutex_unlock(&g_server_conn.mutex);
        return -1;
    }
}

static void session_cleanup()
{
    if (!config.session_enable_timeout)
    {

        return;
    }

    time_t now = time(NULL);
    pthread_mutex_lock(&g_session_mutex);

    for (int i = 0; i < SESSION_HASH_SIZE; i++)
    {
        SessionEntry **pprev = &g_session_table[i];
        while (*pprev)
        {
            SessionEntry *cur = *pprev;
            double diff_seconds = difftime(now, cur->created_at);
            if (diff_seconds > config.session_timeout_seconds)
            {

                log_message(LOG_INFO,
                            "session_cleanup: token=%s, user_id=%d, data_port=%d 超时(%.1f秒)，清理",
                            cur->token, cur->user_id, cur->data_port, diff_seconds);

                if (cur->data_port > 0)
                {
                    close_data_port(cur->data_port);
                }

                *pprev = cur->next;
                free(cur->token);
                free(cur);
            }
            else
            {
                pprev = &cur->next;
            }
        }
    }
    pthread_mutex_unlock(&g_session_mutex);
}

void *session_cleanup_thread(void *arg)
{
    (void)arg;

    while (1)
    {
        session_cleanup();
        sleep(60);
    }
    return NULL;
}

static int searchDeviceReq(uint32_t ulDevID, int socket_fd)
{
    if (socket_fd < 0)
    {
        log_message(LOG_ERROR, "searchDeviceReq: 无效的套接字");
        return -1;
    }

    DevStateRequest request = {
        .serv_flag = 0xFF,
        .serv_cmd = PC_CMD_DEVONLINE_REQ,
        .serv_len = sizeof(request.serv_data),
        .serv_version = 0,
        .serv_data = ulDevID};

    ssize_t bytesSent = send_all(socket_fd, &request, sizeof(request));
    if (bytesSent != sizeof(request))
    {
        log_message(LOG_ERROR, "searchDeviceReq: 发送失败");
        return -1;
    }

    log_message(LOG_DEBUG, "searchDeviceReq: 发送设备状态查询请求成功, DevID=%u", ulDevID);
    return 0;
}

static int searchDeviceRecv(REG_TABLE *regTable, int socket_fd)
{
    if (!regTable || socket_fd < 0)
    {
        return -1;
    }

    memset(regTable, 0, sizeof(REG_TABLE));

    ServHeader serv_header;
    ssize_t bytesReceived = recv_all(socket_fd, &serv_header, sizeof(ServHeader));
    if (bytesReceived != sizeof(ServHeader))
    {
        log_message(LOG_ERROR, "searchDeviceRecv: 接收头部数据失败");
        return -1;
    }

    if (serv_header.serv_cmd != PC_CMD_DEVONLINE_RET)
    {
        log_message(LOG_ERROR, "searchDeviceRecv: 无效的响应命令: 0x%04X", serv_header.serv_cmd);
        return -1;
    }

    if (serv_header.serv_len != sizeof(REG_TABLE))
    {
        log_message(LOG_ERROR, "searchDeviceRecv: 响应数据长度不正确: %u", serv_header.serv_len);
        return -1;
    }

    bytesReceived = recv_all(socket_fd, regTable, sizeof(REG_TABLE));
    if (bytesReceived != sizeof(REG_TABLE))
    {
        log_message(LOG_ERROR, "searchDeviceRecv: 接收数据失败");
        return -1;
    }

    log_message(LOG_DEBUG, "searchDeviceRecv: 接收设备状态响应成功");
    return 0;
}

static int searchDevice(uint32_t ulDevID, const REG_TABLE *regTable)
{
    if (!regTable)
    {
        return 0;
    }

    uint32_t ulPos;
    uint8_t ucMask, ucData, ucState;

    ulPos = (ulDevID - BEGINNUM);
    ulPos = (ulPos & 0x1FFF);
    ulPos = (ulPos >> 3);

    ucMask = (uint8_t)(0x1 << (ulDevID & 0x7));

    if (ulPos < REG_TABLE_SIZE)
    {
        ucData = regTable->ucState[ulPos];
        ucState = ucData & ucMask;

        log_message(LOG_DEBUG, "searchDevice: DevID=%u, Pos=%u, Mask=0x%02X, Data=0x%02X, State=%u",
                    ulDevID, ulPos, ucMask, ucData, (ucState != 0) ? 1 : 0);

        return (ucState == 0) ? 0 : 1;
    }
    else
    {
        log_message(LOG_WARN, "searchDevice: 设备ID超出范围: %u", ulDevID);
        return 0;
    }
}

static REG_TABLE g_reg_table;
static pthread_mutex_t g_reg_table_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_reg_table_initialized = 0;
static time_t g_last_update_time = 0;

static int update_device_status_bitmap()
{
    int socket_fd = -1;

    if (get_server_connection(&socket_fd) != 0)
    {
        log_message(LOG_ERROR, "update_device_status_bitmap: 无法获取服务器连接");
        return -1;
    }

    if (searchDeviceReq(0, socket_fd) != 0)
    {
        log_message(LOG_ERROR, "update_device_status_bitmap: 发送设备状态查询请求失败");

        pthread_mutex_lock(&g_server_conn.mutex);
        g_server_conn.is_connected = 0;
        close(g_server_conn.sockfd);
        g_server_conn.sockfd = -1;
        pthread_mutex_unlock(&g_server_conn.mutex);

        return -1;
    }

    REG_TABLE new_reg_table;
    if (searchDeviceRecv(&new_reg_table, socket_fd) != 0)
    {
        log_message(LOG_ERROR, "update_device_status_bitmap: 接收设备状态响应失败");

        pthread_mutex_lock(&g_server_conn.mutex);
        g_server_conn.is_connected = 0;
        close(g_server_conn.sockfd);
        g_server_conn.sockfd = -1;
        pthread_mutex_unlock(&g_server_conn.mutex);

        return -1;
    }

    pthread_mutex_lock(&g_reg_table_mutex);
    memcpy(&g_reg_table, &new_reg_table, sizeof(REG_TABLE));
    g_reg_table_initialized = 1;
    g_last_update_time = time(NULL);
    pthread_mutex_unlock(&g_reg_table_mutex);

    log_message(LOG_DEBUG, "update_device_status_bitmap: 设备状态位图更新成功");
    return 0;
}

void *device_status_update_thread(void *arg)
{
    (void)arg;

    log_message(LOG_INFO, "设备状态位图更新线程启动");

    while (1)
    {

        sleep(3);

        if (update_device_status_bitmap() != 0)
        {
            log_message(LOG_WARN, "设备状态位图更新失败，3秒后重试");
        }
    }

    return NULL;
}

static int search_device_from_bitmap(uint32_t ulDevID)
{
    if (!g_reg_table_initialized)
    {
        log_message(LOG_WARN, "search_device_from_bitmap: 设备状态位图未初始化");
        return 0;
    }

    pthread_mutex_lock(&g_reg_table_mutex);
    int result = searchDevice(ulDevID, &g_reg_table);
    pthread_mutex_unlock(&g_reg_table_mutex);

    return result;
}

int main(int argc, char *argv[])
{
    signal(SIGPIPE, SIG_IGN);
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    pthread_t tid;

    char *config_content = NULL;
    char *config_path = "config.json";

    if (argc > 1)
        config_path = argv[1];

    if (read_file(config_path, &config_content) != 0)
    {
        fprintf(stderr, "读取配置文件失败\n");
        return -1;
    }

    if (parse_config(config_content, &config) != 0)
    {
        fprintf(stderr, "解析配置文件失败\n");
        free(config_content);
        return -1;
    }
    free(config_content);

    set_log_level_by_string(config.log_level);

    log_message(LOG_INFO, "服务器启动，监听端口 %d", config.server_port);
    log_message(LOG_INFO, "使用数据库: %s@%s:%d/%s",
                config.db_user, config.db_host, config.db_port, config.db_name);
    log_message(LOG_INFO, "日志文件: %s，日志级别: %s",
                config.log_file, config.log_level);

    pthread_t cleanup_tid;
    pthread_create(&cleanup_tid, NULL, session_cleanup_thread, NULL);
    pthread_detach(cleanup_tid);

    pthread_t status_update_tid;
    pthread_create(&status_update_tid, NULL, device_status_update_thread, NULL);
    pthread_detach(status_update_tid);

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        HANDLE_ERROR("socket创建失败");
    }

    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        HANDLE_ERROR("setsockopt失败");
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(config.server_port);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        HANDLE_ERROR("bind失败");
    }

    if (listen(server_sock, 5) < 0)
    {
        HANDLE_ERROR("listen失败");
    }

    log_message(LOG_INFO, "服务器正在监听登录端口 %d...", config.server_port);
    printf("服务器正在监听登录端口 %d...\n", config.server_port);

    while (1)
    {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_sock < 0)
        {
            perror("accept失败");
            log_message(LOG_ERROR, "accept失败: %s", strerror(errno));
            continue;
        }

        int *pclient = (int *)malloc(sizeof(int));
        if (!pclient)
        {
            perror("malloc失败");
            log_message(LOG_ERROR, "malloc失败");
            close(client_sock);
            continue;
        }

        *pclient = client_sock;
        if (pthread_create(&tid, NULL, handle_login_client, pclient) != 0)
        {
            perror("pthread_create失败");
            log_message(LOG_ERROR, "pthread_create失败: %s", strerror(errno));
            close(client_sock);
            free(pclient);
            continue;
        }
        pthread_detach(tid);
    }

    close(server_sock);
    return 0;
}

static int send_error_response(int sockfd, unsigned short cmd, const char *error_msg)
{
    cJSON *resp_json = cJSON_CreateObject();
    if (!resp_json)
        return -1;

    cJSON_AddStringToObject(resp_json, "Error", error_msg);
    char *response = cJSON_PrintUnformatted(resp_json);
    cJSON_Delete(resp_json);

    if (!response)
        return -1;

    uint32_t resp_len = (uint32_t)strlen(response);

    unsigned char resp_header[8];
    resp_header[0] = 0xFF;
    write_le16(resp_header + 1, cmd + 1);
    write_le32(resp_header + 3, resp_len);
    resp_header[7] = (unsigned char)config.protocol_version;

    size_t total_len = 8 + resp_len;
    unsigned char *send_buffer = (unsigned char *)malloc(total_len);
    if (!send_buffer)
    {
        free(response);
        return -1;
    }

    memcpy(send_buffer, resp_header, 8);
    memcpy(send_buffer + 8, response, resp_len);

    ssize_t sent = send_all(sockfd, send_buffer, total_len);
    free(send_buffer);
    free(response);

    return (sent == (ssize_t)total_len) ? 0 : -1;
}

int read_file(const char *filename, char **content)
{
    FILE *fp = fopen(filename, "r");
    if (!fp)
    {
        perror("打开配置文件失败");
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0)
    {
        perror("fseek失败");
        fclose(fp);
        return -1;
    }

    long filesize = ftell(fp);
    if (filesize < 0)
    {
        perror("ftell失败");
        fclose(fp);
        return -1;
    }
    rewind(fp);

    *content = (char *)malloc(filesize + 1);
    if (!*content)
    {
        perror("分配内存失败");
        fclose(fp);
        return -1;
    }

    size_t read_size = fread(*content, 1, filesize, fp);
    fclose(fp);

    if (read_size != (size_t)filesize)
    {
        perror("读取配置文件失败");
        free(*content);
        return -1;
    }

    (*content)[filesize] = '\0';
    return 0;
}

int parse_config(const char *json_str, Config *cfg)
{
    cJSON *json = cJSON_Parse(json_str);
    if (!json)
    {
        fprintf(stderr, "配置文件JSON解析失败\n");
        return -1;
    }

    cJSON *server = cJSON_GetObjectItemCaseSensitive(json, "server");
    if (cJSON_IsObject(server))
    {
        cJSON *port = cJSON_GetObjectItemCaseSensitive(server, "port");
        cJSON *pv = cJSON_GetObjectItemCaseSensitive(server, "protocol_version");
        if (cJSON_IsNumber(port))
            cfg->server_port = port->valueint;
        else
            cfg->server_port = 28600;

        if (cJSON_IsNumber(pv))
            cfg->protocol_version = pv->valueint;
        else
            cfg->protocol_version = 1;
    }
    else
    {
        cfg->server_port = 28600;
        cfg->protocol_version = 1;
    }

    cJSON *database = cJSON_GetObjectItemCaseSensitive(json, "database");
    if (cJSON_IsObject(database))
    {
        cJSON *host = cJSON_GetObjectItemCaseSensitive(database, "host");
        cJSON *user = cJSON_GetObjectItemCaseSensitive(database, "user");
        cJSON *password = cJSON_GetObjectItemCaseSensitive(database, "password");
        cJSON *dbname = cJSON_GetObjectItemCaseSensitive(database, "dbname");
        cJSON *port_db = cJSON_GetObjectItemCaseSensitive(database, "port");

        if (cJSON_IsString(host))
            strncpy(cfg->db_host, host->valuestring, sizeof(cfg->db_host) - 1);

        if (cJSON_IsString(user))
            strncpy(cfg->db_user, user->valuestring, sizeof(cfg->db_user) - 1);

        if (cJSON_IsString(password))
            strncpy(cfg->db_password, password->valuestring, sizeof(cfg->db_password) - 1);

        if (cJSON_IsString(dbname))
            strncpy(cfg->db_name, dbname->valuestring, sizeof(cfg->db_name) - 1);

        if (cJSON_IsNumber(port_db))
            cfg->db_port = port_db->valueint;
        else
            cfg->db_port = 3306;
    }
    else
    {
        fprintf(stderr, "错误：缺少 database 配置\n");
        cJSON_Delete(json);
        return -1;
    }

    cJSON *logging = cJSON_GetObjectItemCaseSensitive(json, "logging");
    if (cJSON_IsObject(logging))
    {
        cJSON *log_file = cJSON_GetObjectItemCaseSensitive(logging, "log_file");
        cJSON *log_level = cJSON_GetObjectItemCaseSensitive(logging, "log_level");

        if (cJSON_IsString(log_file))
            strncpy(cfg->log_file, log_file->valuestring, sizeof(cfg->log_file) - 1);
        else
            strncpy(cfg->log_file, "middleware.log", sizeof(cfg->log_file) - 1);

        if (cJSON_IsString(log_level))
            strncpy(cfg->log_level, log_level->valuestring, sizeof(cfg->log_level) - 1);
        else
            strncpy(cfg->log_level, "INFO", sizeof(cfg->log_level) - 1);
    }
    else
    {
        strncpy(cfg->log_file, "middleware.log", sizeof(cfg->log_file) - 1);
        strncpy(cfg->log_level, "INFO", sizeof(cfg->log_level) - 1);
    }

    cJSON *session = cJSON_GetObjectItemCaseSensitive(json, "session");
    if (cJSON_IsObject(session))
    {
        cJSON *enable_timeout = cJSON_GetObjectItemCaseSensitive(session, "enable_timeout");
        cJSON *timeout_seconds = cJSON_GetObjectItemCaseSensitive(session, "timeout_seconds");

        if (cJSON_IsBool(enable_timeout))
            cfg->session_enable_timeout = cJSON_IsTrue(enable_timeout) ? 1 : 0;
        else
            cfg->session_enable_timeout = 1;

        if (cJSON_IsNumber(timeout_seconds))
            cfg->session_timeout_seconds = timeout_seconds->valueint;
        else
            cfg->session_timeout_seconds = 7200;
    }
    else
    {
        cfg->session_enable_timeout = 1;
        cfg->session_timeout_seconds = 7200;
    }

    cJSON *data_port = cJSON_GetObjectItemCaseSensitive(json, "data_port");
    if (cJSON_IsObject(data_port))
    {

        cJSON *enable_timeout_dp = cJSON_GetObjectItemCaseSensitive(data_port, "enable_timeout");
        if (cJSON_IsBool(enable_timeout_dp))
            cfg->data_port_enable_timeout = cJSON_IsTrue(enable_timeout_dp) ? 1 : 0;
        else
            cfg->data_port_enable_timeout = 1;

        cJSON *timeout_seconds_dp = cJSON_GetObjectItemCaseSensitive(data_port, "timeout_seconds");
        if (cJSON_IsNumber(timeout_seconds_dp))
            cfg->data_port_timeout_seconds = timeout_seconds_dp->valueint;
        else
            cfg->data_port_timeout_seconds = 900;
    }
    else
    {

        cfg->data_port_enable_timeout = 1;
        cfg->data_port_timeout_seconds = 900;
    }

    cJSON *server_info = cJSON_GetObjectItemCaseSensitive(json, "server_info");
    if (cJSON_IsObject(server_info))
    {
        cJSON *port = cJSON_GetObjectItemCaseSensitive(server_info, "port");
        cJSON *address = cJSON_GetObjectItemCaseSensitive(server_info, "address");
        if (cJSON_IsNumber(port))
            cfg->port = port->valueint;
        else
            cfg->port = 29000;

        if (cJSON_IsString(address))
            strncpy(cfg->address, address->valuestring, sizeof(cfg->address) - 1);
        else
            strncpy(cfg->address, "127.0.0.1", sizeof(cfg->address) - 1);
    }
    else
    {
        strncpy(cfg->address, "127.0.0.1", sizeof(cfg->address) - 1);
        cfg->port = 29000;
    }

    cJSON_Delete(json);
    return 0;
}

int handle_request(
    unsigned short cmd,
    char *data,
    uint32_t data_len,
    MYSQL *conn,
    char **response,
    uint32_t *resp_len,
    const char *expected_token)
{
    cJSON *json = NULL;

    if (data_len > 0 && data)
    {
        json = cJSON_Parse(data);
        if (!json)
        {
            log_message(LOG_WARN, "handle_request: JSON解析失败");
            return -1;
        }
    }
    else
    {
        json = cJSON_CreateObject();
    }

    int ret = -1;
    switch (cmd)
    {
    case 0x0001:

        ret = handle_login(json, conn, response, resp_len);
        break;

    case 0x0003:
        ret = handle_dclistreq(json, conn, response, resp_len);
        break;

    case 0x0005:
        ret = handle_devlistreq(json, conn, response, resp_len);
        break;

    case 0x0007:
        ret = handle_devstatereq(json, conn, response, resp_len);
        break;

    default:
        log_message(LOG_WARN, "handle_request: 未知指令码 %u", cmd);
        ret = -1;
        break;
    }

    if (json)
        cJSON_Delete(json);
    return ret;
}

int handle_login(cJSON *json, MYSQL *conn, char **response, uint32_t *resp_len)
{
    cJSON *user_item = cJSON_GetObjectItemCaseSensitive(json, "LoginUser");
    cJSON *pwd_item = cJSON_GetObjectItemCaseSensitive(json, "LoginPwd");

    cJSON *resp_json = cJSON_CreateObject();
    if (!cJSON_IsString(user_item) || !cJSON_IsString(pwd_item))
    {
        log_message(LOG_WARN, "handle_login: 参数无效");
        cJSON_AddNumberToObject(resp_json, "Ret", -1);
        goto END_LOGIN;
    }

    size_t encoded_len = 0;
    char *encoded_pwd = base64_encode(
        (unsigned char *)pwd_item->valuestring,
        strlen(pwd_item->valuestring),
        &encoded_len);
    if (!encoded_pwd)
    {
        log_message(LOG_ERROR, "handle_login: Base64编码失败");
        cJSON_AddNumberToObject(resp_json, "Ret", -1);
        goto END_LOGIN;
    }

    const char *stmt_str =
        "SELECT uid FROM tbl_user WHERE userName = ? AND passWord = ?";

    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if (!stmt)
    {
        log_message(LOG_ERROR, "handle_login: mysql_stmt_init失败");
        free(encoded_pwd);
        cJSON_AddNumberToObject(resp_json, "Ret", -1);
        goto END_LOGIN;
    }

    if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str)) != 0)
    {
        log_message(LOG_ERROR, "handle_login: mysql_stmt_prepare失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        free(encoded_pwd);
        cJSON_AddNumberToObject(resp_json, "Ret", -1);
        goto END_LOGIN;
    }

    MYSQL_BIND bind_param[2];
    memset(bind_param, 0, sizeof(bind_param));
    bind_param[0].buffer_type = MYSQL_TYPE_STRING;
    bind_param[0].buffer = (char *)user_item->valuestring;
    bind_param[0].buffer_length = strlen(user_item->valuestring);

    bind_param[1].buffer_type = MYSQL_TYPE_STRING;
    bind_param[1].buffer = encoded_pwd;
    bind_param[1].buffer_length = encoded_len;

    if (mysql_stmt_bind_param(stmt, bind_param) != 0)
    {
        log_message(LOG_ERROR, "handle_login: mysql_stmt_bind_param失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        free(encoded_pwd);
        cJSON_AddNumberToObject(resp_json, "Ret", -1);
        goto END_LOGIN;
    }

    if (mysql_stmt_execute(stmt) != 0)
    {
        log_message(LOG_ERROR, "handle_login: mysql_stmt_execute失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        free(encoded_pwd);
        cJSON_AddNumberToObject(resp_json, "Ret", -1);
        goto END_LOGIN;
    }

    MYSQL_BIND bind_result[1];
    memset(bind_result, 0, sizeof(bind_result));
    int user_id = -1;
    bind_result[0].buffer_type = MYSQL_TYPE_LONG;
    bind_result[0].buffer = &user_id;

    if (mysql_stmt_bind_result(stmt, bind_result) != 0)
    {
        log_message(LOG_ERROR, "handle_login: mysql_stmt_bind_result失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        free(encoded_pwd);
        cJSON_AddNumberToObject(resp_json, "Ret", -1);
        goto END_LOGIN;
    }

    if (mysql_stmt_store_result(stmt) != 0)
    {
        log_message(LOG_ERROR, "handle_login: mysql_stmt_store_result失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        free(encoded_pwd);
        cJSON_AddNumberToObject(resp_json, "Ret", -1);
        goto END_LOGIN;
    }

    if (mysql_stmt_num_rows(stmt) == 0)
    {

        cJSON_AddNumberToObject(resp_json, "Ret", 0);
        cJSON_AddStringToObject(resp_json, "Data", "null");
        log_message(LOG_INFO, "handle_login: 用户名/密码不匹配");
    }
    else
    {
        if (mysql_stmt_fetch(stmt) == 0)
        {

            char *token = generate_random_token_base64();
            if (!token)
            {
                cJSON_AddNumberToObject(resp_json, "Ret", -1);
                log_message(LOG_ERROR, "handle_login: 生成随机token失败");
            }
            else
            {

                if (session_store(token, user_id, -1) != 0)
                {
                    free(token);
                    cJSON_AddNumberToObject(resp_json, "Ret", -1);
                    log_message(LOG_ERROR, "handle_login: session_store失败");
                }
                else
                {

                    cJSON_AddNumberToObject(resp_json, "Ret", 1);
                    cJSON *data_obj = cJSON_CreateObject();
                    cJSON_AddStringToObject(data_obj, "LoginID", token);
                    cJSON_AddStringToObject(data_obj, "LoginRet", "DataPort");
                    cJSON_AddItemToObject(resp_json, "Data", data_obj);

                    log_message(LOG_INFO, "handle_login: user_id=%d 登录成功, token=%s", user_id, token);
                    free(token);
                }
            }
        }
        else
        {

            cJSON_AddNumberToObject(resp_json, "Ret", -1);
            log_message(LOG_WARN, "handle_login: mysql_stmt_fetch失败");
        }
    }

    mysql_stmt_close(stmt);
    free(encoded_pwd);

END_LOGIN:;
    *response = cJSON_PrintUnformatted(resp_json);
    if (!*response)
    {
        log_message(LOG_ERROR, "handle_login: cJSON_PrintUnformatted失败");
        cJSON_Delete(resp_json);
        return -1;
    }
    *resp_len = (uint32_t)strlen(*response);
    cJSON_Delete(resp_json);
    return 0;
}

int handle_dclistreq(cJSON *json, MYSQL *conn, char **response, uint32_t *resp_len)
{

    cJSON *station_req_item = cJSON_GetObjectItemCaseSensitive(json, "StationReq");
    cJSON *login_id_item = cJSON_GetObjectItemCaseSensitive(json, "LoginID");

    cJSON *resp_json = cJSON_CreateObject();
    if (!cJSON_IsString(station_req_item) || !cJSON_IsString(login_id_item))
    {
        log_message(LOG_WARN, "handle_dclistreq: 参数无效");

        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DC;
    }

    int user_id = session_lookup(login_id_item->valuestring);
    if (user_id < 0)
    {

        log_message(LOG_WARN, "handle_dclistreq: Token无效");
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DC;
    }

    char user_id_str[20];
    snprintf(user_id_str, sizeof(user_id_str), "%d", user_id);

    const char *stmt_str =
        "SELECT s.stasionName "
        "FROM tbl_stasion AS s "
        "LEFT JOIN tbl_userlinkstasion AS u ON s.sid = u.sid "
        "WHERE u.uid = ?";

    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if (!stmt)
    {
        log_message(LOG_ERROR, "handle_dclistreq: mysql_stmt_init 失败");
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DC;
    }

    if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str)) != 0)
    {
        log_message(LOG_ERROR, "handle_dclistreq: prepare失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DC;
    }

    MYSQL_BIND bind_param[1];
    memset(bind_param, 0, sizeof(bind_param));
    bind_param[0].buffer_type = MYSQL_TYPE_STRING;
    bind_param[0].buffer = user_id_str;
    bind_param[0].buffer_length = strlen(user_id_str);

    if (mysql_stmt_bind_param(stmt, bind_param) != 0)
    {
        log_message(LOG_ERROR, "handle_dclistreq: bind_param失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DC;
    }

    if (mysql_stmt_execute(stmt) != 0)
    {
        log_message(LOG_ERROR, "handle_dclistreq: execute失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DC;
    }

    MYSQL_BIND bind_result[1];
    memset(bind_result, 0, sizeof(bind_result));

    char dc_name[256];
    unsigned long dc_name_length;

    bind_result[0].buffer_type = MYSQL_TYPE_STRING;
    bind_result[0].buffer = dc_name;
    bind_result[0].buffer_length = sizeof(dc_name);
    bind_result[0].length = &dc_name_length;

    if (mysql_stmt_bind_result(stmt, bind_result) != 0)
    {
        log_message(LOG_ERROR, "handle_dclistreq: bind_result失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DC;
    }

    if (mysql_stmt_store_result(stmt) != 0)
    {
        log_message(LOG_ERROR, "handle_dclistreq: store_result失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DC;
    }

    {

        int row_count = (int)mysql_stmt_num_rows(stmt);
        if (row_count == 0)
        {

            cJSON_AddStringToObject(resp_json, "Ret", "0");
            cJSON_AddStringToObject(resp_json, "DC", "null");
        }
        else
        {

            cJSON_AddStringToObject(resp_json, "Ret", "1");

            int idx = 1;
            while (mysql_stmt_fetch(stmt) == 0)
            {

                dc_name[dc_name_length] = '\0';

                char key[20];
                snprintf(key, sizeof(key), "DC%d", idx);

                cJSON_AddStringToObject(resp_json, key, dc_name);

                idx++;
            }
        }
    }

    mysql_stmt_close(stmt);

END_DC:;

    *response = cJSON_PrintUnformatted(resp_json);
    if (!*response)
    {
        log_message(LOG_ERROR, "handle_dclistreq: cJSON_PrintUnformatted失败");
        cJSON_Delete(resp_json);
        return -1;
    }

    *resp_len = (uint32_t)strlen(*response);
    cJSON_Delete(resp_json);
    return 0;
}

int handle_devlistreq(cJSON *json, MYSQL *conn, char **response, uint32_t *resp_len)
{

    cJSON *dc_item = cJSON_GetObjectItemCaseSensitive(json, "DC");
    cJSON *login_id_item = cJSON_GetObjectItemCaseSensitive(json, "LoginID");

    cJSON *resp_json = cJSON_CreateObject();

    if (!cJSON_IsString(dc_item) || !cJSON_IsString(login_id_item))
    {
        log_message(LOG_WARN, "handle_devlistreq: 参数无效");
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DEV;
    }

    int user_id = session_lookup(login_id_item->valuestring);
    if (user_id < 0)
    {
        log_message(LOG_WARN, "handle_devlistreq: Token无效");
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DEV;
    }

    char user_id_str[20];
    snprintf(user_id_str, sizeof(user_id_str), "%d", user_id);

    const char *stmt_str =
        "SELECT CONCAT(d.serialNum, '_', d.deviceName) AS name_num "
        "FROM tbl_device AS d "
        "LEFT JOIN tbl_stasion AS s ON d.sid = s.sid "
        "LEFT JOIN tbl_userlinkstasion AS u ON s.sid = u.sid "
        "WHERE d.type = '4G' AND s.stasionName = ? AND u.uid = ?";

    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if (!stmt)
    {
        log_message(LOG_ERROR, "handle_devlistreq: mysql_stmt_init失败");
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DEV;
    }

    if (mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str)) != 0)
    {
        log_message(LOG_ERROR, "handle_devlistreq: prepare失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DEV;
    }

    MYSQL_BIND bind_param[2];
    memset(bind_param, 0, sizeof(bind_param));

    bind_param[0].buffer_type = MYSQL_TYPE_STRING;
    bind_param[0].buffer = (char *)dc_item->valuestring;
    bind_param[0].buffer_length = strlen(dc_item->valuestring);

    bind_param[1].buffer_type = MYSQL_TYPE_STRING;
    bind_param[1].buffer = user_id_str;
    bind_param[1].buffer_length = strlen(user_id_str);

    if (mysql_stmt_bind_param(stmt, bind_param) != 0)
    {
        log_message(LOG_ERROR, "handle_devlistreq: bind_param失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DEV;
    }

    if (mysql_stmt_execute(stmt) != 0)
    {
        log_message(LOG_ERROR, "handle_devlistreq: execute失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DEV;
    }

    MYSQL_BIND bind_result[1];
    memset(bind_result, 0, sizeof(bind_result));

    char device_name[256];
    unsigned long device_name_length;

    bind_result[0].buffer_type = MYSQL_TYPE_STRING;
    bind_result[0].buffer = device_name;
    bind_result[0].buffer_length = sizeof(device_name);
    bind_result[0].length = &device_name_length;

    if (mysql_stmt_bind_result(stmt, bind_result) != 0)
    {
        log_message(LOG_ERROR, "handle_devlistreq: bind_result失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DEV;
    }

    if (mysql_stmt_store_result(stmt) != 0)
    {
        log_message(LOG_ERROR, "handle_devlistreq: store_result失败: %s", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DEV;
    }

    int row_count = (int)mysql_stmt_num_rows(stmt);
    if (row_count == 0)
    {
        cJSON_AddStringToObject(resp_json, "Ret", "0");
        cJSON_AddStringToObject(resp_json, "Dev", "null");
    }
    else
    {
        cJSON_AddStringToObject(resp_json, "Ret", "1");

        int idx = 1;
        while (mysql_stmt_fetch(stmt) == 0)
        {
            device_name[device_name_length] = '\0';

            char key[20];
            snprintf(key, sizeof(key), "Dev%d", idx);

            cJSON_AddStringToObject(resp_json, key, device_name);
            idx++;
        }
    }

    mysql_stmt_close(stmt);

END_DEV:

    *response = cJSON_PrintUnformatted(resp_json);
    if (!*response)
    {
        log_message(LOG_ERROR, "handle_devlistreq: cJSON_PrintUnformatted失败");
        cJSON_Delete(resp_json);
        return -1;
    }

    *resp_len = (uint32_t)strlen(*response);
    cJSON_Delete(resp_json);
    return 0;
}

int handle_devstatereq(cJSON *json, MYSQL *conn, char **response, uint32_t *resp_len)
{
    cJSON *dev_id_item = cJSON_GetObjectItemCaseSensitive(json, "DevStateReq");
    cJSON *login_id_item = cJSON_GetObjectItemCaseSensitive(json, "LoginID");

    cJSON *resp_json = cJSON_CreateObject();

    if (!cJSON_IsString(dev_id_item) || !cJSON_IsString(login_id_item))
    {
        log_message(LOG_WARN, "handle_devstatereq: 参数无效");
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DEVSTATE;
    }

    int user_id = session_lookup(login_id_item->valuestring);
    if (user_id < 0)
    {
        log_message(LOG_WARN, "handle_devstatereq: 无效的 Token");
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DEVSTATE;
    }

    uint32_t device_id = (uint32_t)atoi(dev_id_item->valuestring);
    if (device_id == 0)
    {
        log_message(LOG_WARN, "handle_devstatereq: 无效的设备 ID");
        cJSON_AddStringToObject(resp_json, "Ret", "-1");
        goto END_DEVSTATE;
    }

    int device_online = search_device_from_bitmap(device_id);

    char rtsp_url[256];
    snprintf(rtsp_url, sizeof(rtsp_url), "rtsp://%s/%s",
             config.address, dev_id_item->valuestring);

    if (device_online == 1)
    {
        log_message(LOG_INFO, "handle_devstatereq: 设备在线 DevID=%u", device_id);
        cJSON_AddStringToObject(resp_json, "Ret", "1");
        cJSON_AddStringToObject(resp_json, "DevID", dev_id_item->valuestring);
        cJSON_AddStringToObject(resp_json, "DevRtsp", rtsp_url);
    }
    else
    {
        log_message(LOG_INFO, "handle_devstatereq: 设备离线 DevID=%u", device_id);
        cJSON_AddStringToObject(resp_json, "Ret", "0");
        cJSON_AddStringToObject(resp_json, "DevID", dev_id_item->valuestring);
    }

END_DEVSTATE:
    *response = cJSON_PrintUnformatted(resp_json);
    if (!*response)
    {
        log_message(LOG_ERROR, "handle_devstatereq: cJSON_PrintUnformatted失败");
        cJSON_Delete(resp_json);
        return -1;
    }

    *resp_len = strlen(*response);
    cJSON_Delete(resp_json);
    return 0;
}

static int send_response_packet(int sockfd, unsigned short cmd, const char *json_str)
{
    uint32_t resp_len = (uint32_t)strlen(json_str);
    unsigned char resp_header[8];

    resp_header[0] = 0xFF;
    write_le16(resp_header + 1, cmd + 1);
    write_le32(resp_header + 3, resp_len);
    resp_header[7] = (unsigned char)config.protocol_version;

    size_t total_len = 8 + resp_len;
    unsigned char *send_buf = (unsigned char *)malloc(total_len);
    if (!send_buf)
        return -1;

    memcpy(send_buf, resp_header, 8);
    memcpy(send_buf + 8, json_str, resp_len);

    ssize_t sent = send_all(sockfd, send_buf, total_len);
    free(send_buf);

    return (sent == (ssize_t)total_len) ? 0 : -1;
}

void *handle_login_client(void *arg)
{
    int client_sock = *((int *)arg);
    free(arg);

    log_message(LOG_DEBUG, "handle_login_client: 新连接 (sock=%d)", client_sock);

    unsigned char header[8];
    ssize_t n = recv_all(client_sock, header, 8);
    if (n <= 0)
    {
        if (n < 0)
            log_message(LOG_ERROR, "handle_login_client: recv头部失败 (sock=%d): %s", client_sock, strerror(errno));
        else
            log_message(LOG_INFO, "handle_login_client: 客户端主动关闭 (sock=%d)", client_sock);

        close(client_sock);
        pthread_exit(NULL);
    }
    else if (n != 8 || header[0] != 0xFF)
    {
        log_message(LOG_WARN, "handle_login_client: 不完整或无效头部 (sock=%d)", client_sock);
        close(client_sock);
        pthread_exit(NULL);
    }

    unsigned short cmd = read_le16(header + 1);
    uint32_t data_len = read_le32(header + 3);
    unsigned char version = header[7];

    if (version != config.protocol_version)
    {
        log_message(LOG_WARN, "handle_login_client: 协议版本不匹配 (sock=%d)", client_sock);
        close(client_sock);
        pthread_exit(NULL);
    }

    if (cmd != 0x0001)
    {
        log_message(LOG_WARN, "handle_login_client: 非登录指令 0x%04X (sock=%d)", cmd, client_sock);
        close(client_sock);
        pthread_exit(NULL);
    }

    char *data = NULL;
    if (data_len > 0)
    {
        data = (char *)malloc(data_len + 1);
        if (!data)
        {
            log_message(LOG_ERROR, "handle_login_client: malloc data失败 (sock=%d)", client_sock);
            close(client_sock);
            pthread_exit(NULL);
        }

        n = recv_all(client_sock, data, data_len);
        if (n <= 0)
        {
            log_message(LOG_ERROR, "handle_login_client: recv data失败 (sock=%d): %s", client_sock, strerror(errno));
            free(data);
            close(client_sock);
            pthread_exit(NULL);
        }
        else if ((uint32_t)n != data_len)
        {
            log_message(LOG_WARN, "handle_login_client: data不完整 (sock=%d)", client_sock);
            free(data);
            close(client_sock);
            pthread_exit(NULL);
        }
        data[data_len] = '\0';
        log_message(LOG_DEBUG, "handle_login_client: 收到登录请求 JSON=%s", data);
    }

    MYSQL *conn_mysql = mysql_init(NULL);
    if (!conn_mysql)
    {
        log_message(LOG_ERROR, "handle_login_client: mysql_init失败");
        if (data)
            free(data);
        close(client_sock);
        pthread_exit(NULL);
    }

    if (!mysql_real_connect(conn_mysql, config.db_host, config.db_user, config.db_password,
                            config.db_name, config.db_port, NULL, 0))
    {
        log_message(LOG_ERROR, "handle_login_client: 连接数据库失败: %s", mysql_error(conn_mysql));
        mysql_close(conn_mysql);
        if (data)
            free(data);
        close(client_sock);
        pthread_exit(NULL);
    }

    if (mysql_set_character_set(conn_mysql, "utf8") != 0)
    {
        log_message(LOG_ERROR, "handle_login_client: 设置字符集失败: %s", mysql_error(conn_mysql));
        mysql_close(conn_mysql);
        if (data)
            free(data);
        close(client_sock);
        pthread_exit(NULL);
    }

    char *response = NULL;
    uint32_t resp_len = 0;
    if (handle_request(cmd, data, data_len, conn_mysql, &response, &resp_len, NULL) < 0)
    {
        log_message(LOG_WARN, "handle_login_client: 登录处理失败 (sock=%d)", client_sock);
        if (response)
            free(response);
        if (data)
            free(data);
        mysql_close(conn_mysql);
        close(client_sock);
        pthread_exit(NULL);
    }

    cJSON *resp_json = cJSON_Parse(response);
    if (!resp_json)
    {
        log_message(LOG_WARN, "handle_login_client: 登录响应JSON解析失败 (sock=%d)", client_sock);
        send_error_response(client_sock, cmd, "Internal Server Error");
        free(response);
        if (data)
            free(data);
        mysql_close(conn_mysql);
        close(client_sock);
        pthread_exit(NULL);
    }

    cJSON *ret_item = cJSON_GetObjectItemCaseSensitive(resp_json, "Ret");
    if (!cJSON_IsNumber(ret_item))
    {
        log_message(LOG_WARN, "handle_login_client: 响应中无Ret (sock=%d)", client_sock);
        send_error_response(client_sock, cmd, "Internal Server Error");
        cJSON_Delete(resp_json);
        free(response);
        if (data)
            free(data);
        mysql_close(conn_mysql);
        close(client_sock);
        pthread_exit(NULL);
    }

    if (ret_item->valueint != 1)
    {
        log_message(LOG_INFO, "handle_login_client: 登录失败 Ret=%d (sock=%d)",
                    ret_item->valueint, client_sock);
        send_error_response(client_sock, cmd, "Authentication Failed");
        cJSON_Delete(resp_json);
        free(response);
        if (data)
            free(data);
        mysql_close(conn_mysql);
        close(client_sock);
        pthread_exit(NULL);
    }

    int data_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (data_listen_sock < 0)
    {
        log_message(LOG_ERROR, "handle_login_client: 创建 data_port socket失败: %s", strerror(errno));
        cJSON_Delete(resp_json);
        free(response);
        if (data)
            free(data);
        mysql_close(conn_mysql);
        close(client_sock);
        pthread_exit(NULL);
    }

    int opt_val = 1;
    setsockopt(data_listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));

    struct sockaddr_in data_addr;
    memset(&data_addr, 0, sizeof(data_addr));
    data_addr.sin_family = AF_INET;
    data_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    data_addr.sin_port = htons(0);

    if (bind(data_listen_sock, (struct sockaddr *)&data_addr, sizeof(data_addr)) < 0)
    {
        log_message(LOG_ERROR, "handle_login_client: bind data_port失败: %s", strerror(errno));
        close(data_listen_sock);
        cJSON_Delete(resp_json);
        free(response);
        if (data)
            free(data);
        mysql_close(conn_mysql);
        close(client_sock);
        pthread_exit(NULL);
    }

    socklen_t addr_len = sizeof(data_addr);
    if (getsockname(data_listen_sock, (struct sockaddr *)&data_addr, &addr_len) < 0)
    {
        log_message(LOG_ERROR, "handle_login_client: getsockname失败: %s", strerror(errno));
        close(data_listen_sock);
        cJSON_Delete(resp_json);
        free(response);
        if (data)
            free(data);
        mysql_close(conn_mysql);
        close(client_sock);
        pthread_exit(NULL);
    }

    int data_port = ntohs(data_addr.sin_port);

    if (listen(data_listen_sock, 1) < 0)
    {
        log_message(LOG_ERROR, "handle_login_client: listen data_port失败: %s", strerror(errno));
        close(data_listen_sock);
        cJSON_Delete(resp_json);
        free(response);
        if (data)
            free(data);
        mysql_close(conn_mysql);
        close(client_sock);
        pthread_exit(NULL);
    }

    cJSON *data_item = cJSON_GetObjectItemCaseSensitive(resp_json, "Data");
    if (!cJSON_IsObject(data_item))
    {
        log_message(LOG_WARN, "handle_login_client: 响应中 Data不是对象 (sock=%d)", client_sock);
        send_error_response(client_sock, cmd, "Authentication Failed");
        close(data_listen_sock);
        cJSON_Delete(resp_json);
        free(response);
        if (data)
            free(data);
        mysql_close(conn_mysql);
        close(client_sock);
        pthread_exit(NULL);
    }

    cJSON *login_id_field = cJSON_GetObjectItemCaseSensitive(data_item, "LoginID");
    if (!cJSON_IsString(login_id_field))
    {
        log_message(LOG_WARN, "handle_login_client: 响应中无LoginID (sock=%d)", client_sock);
        send_error_response(client_sock, cmd, "Authentication Failed");
        close(data_listen_sock);
        cJSON_Delete(resp_json);
        free(response);
        if (data)
            free(data);
        mysql_close(conn_mysql);
        close(client_sock);
        pthread_exit(NULL);
    }

    DataPortInfo *dp_info = (DataPortInfo *)malloc(sizeof(DataPortInfo));
    if (!dp_info)
    {
        log_message(LOG_ERROR, "handle_login_client: malloc DataPortInfo失败");
        close(data_listen_sock);
        cJSON_Delete(resp_json);
        free(response);
        if (data)
            free(data);
        mysql_close(conn_mysql);
        close(client_sock);
        pthread_exit(NULL);
    }
    dp_info->data_port = data_port;
    dp_info->data_listen_sock = data_listen_sock;
    strncpy(dp_info->login_id, login_id_field->valuestring, sizeof(dp_info->login_id) - 1);
    dp_info->login_id[sizeof(dp_info->login_id) - 1] = '\0';

    pthread_t data_tid;
    if (pthread_create(&data_tid, NULL, handle_data_client, dp_info) != 0)
    {
        log_message(LOG_ERROR, "handle_login_client: 创建 data_port 线程失败: %s", strerror(errno));
        free(dp_info);
        close(data_listen_sock);
        cJSON_Delete(resp_json);
        free(response);
        if (data)
            free(data);
        mysql_close(conn_mysql);
        close(client_sock);
        pthread_exit(NULL);
    }
    pthread_detach(data_tid);

    session_store(login_id_field->valuestring, session_lookup(login_id_field->valuestring), data_port);

    cJSON *final_json = cJSON_CreateObject();
    cJSON_AddNumberToObject(final_json, "DataPort", data_port);
    cJSON_AddStringToObject(final_json, "LoginID", login_id_field->valuestring);

    char *final_str = cJSON_PrintUnformatted(final_json);
    if (!final_str)
    {
        log_message(LOG_ERROR, "handle_login_client: 生成最终JSON失败");
        cJSON_Delete(final_json);
        close(data_listen_sock);
        cJSON_Delete(resp_json);
        free(response);
        if (data)
            free(data);
        mysql_close(conn_mysql);
        close(client_sock);
        pthread_exit(NULL);
    }

    if (send_response_packet(client_sock, cmd, final_str) != 0)
    {
        log_message(LOG_ERROR, "handle_login_client: 发送响应失败 (sock=%d)", client_sock);
    }
    else
    {
        log_message(LOG_INFO, "handle_login_client: 登录成功, DataPort=%d, token=%s (sock=%d)",
                    data_port, login_id_field->valuestring, client_sock);
    }

    free(final_str);
    cJSON_Delete(final_json);
    cJSON_Delete(resp_json);
    free(response);
    if (data)
        free(data);
    mysql_close(conn_mysql);
    close(client_sock);

    pthread_exit(NULL);
}

void *handle_data_client(void *arg)
{
    DataPortInfo *info = (DataPortInfo *)arg;
    int data_port = info->data_port;
    int data_listen_sock = info->data_listen_sock;
    char token_plus[256];
    strncpy(token_plus, info->login_id, sizeof(token_plus) - 1);
    token_plus[sizeof(token_plus) - 1] = '\0';
    free(info);

    log_message(LOG_INFO, "handle_data_client: token=%s, data_port=%d, listen_sock=%d",
                token_plus, data_port, data_listen_sock);

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int data_client_sock = accept(data_listen_sock, (struct sockaddr *)&client_addr, &client_addr_len);
    if (data_client_sock < 0)
    {
        log_message(LOG_ERROR, "handle_data_client: accept失败: %s", strerror(errno));
        close(data_listen_sock);
        pthread_exit(NULL);
    }

    close(data_listen_sock);

    MYSQL *conn_mysql = mysql_init(NULL);
    if (!conn_mysql)
    {
        log_message(LOG_ERROR, "handle_data_client: mysql_init失败");
        close(data_client_sock);
        pthread_exit(NULL);
    }

    if (!mysql_real_connect(conn_mysql, config.db_host, config.db_user,
                            config.db_password, config.db_name, config.db_port, NULL, 0))
    {
        log_message(LOG_ERROR, "handle_data_client: 连接数据库失败: %s", mysql_error(conn_mysql));
        mysql_close(conn_mysql);
        close(data_client_sock);
        pthread_exit(NULL);
    }

    if (mysql_set_character_set(conn_mysql, "utf8") != 0)
    {
        log_message(LOG_ERROR, "handle_data_client: 设置字符集失败: %s", mysql_error(conn_mysql));
        mysql_close(conn_mysql);
        close(data_client_sock);
        pthread_exit(NULL);
    }

    while (1)
    {

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(data_client_sock, &read_fds);

        struct timeval timeout;
        if (config.data_port_enable_timeout)
        {
            timeout.tv_sec = config.data_port_timeout_seconds;
            timeout.tv_usec = 0;
        }

        int sel_res = 0;
        if (ENABLE_DATA_PORT_TIMEOUT)
        {
            sel_res = select(data_client_sock + 1, &read_fds, NULL, NULL, &timeout);
            if (sel_res < 0)
            {
                log_message(LOG_ERROR, "handle_data_client: select失败: %s", strerror(errno));
                break;
            }
            else if (sel_res == 0)
            {

                log_message(LOG_INFO, "handle_data_client: token=%s, data_port=%d 超时关闭",
                            token_plus, data_port);
                break;
            }
        }

        unsigned char header[8];
        ssize_t n = recv_all(data_client_sock, header, 8);
        if (n == 0)
        {
            log_message(LOG_INFO, "handle_data_client: 客户端关闭 (sock=%d)", data_client_sock);
            break;
        }
        else if (n < 0)
        {
            log_message(LOG_ERROR, "handle_data_client: recv头部失败 (sock=%d): %s",
                        data_client_sock, strerror(errno));
            break;
        }
        else if (n != 8 || header[0] != 0xFF)
        {
            log_message(LOG_WARN, "handle_data_client: 无效或不完整头部 (sock=%d)", data_client_sock);
            break;
        }

        unsigned short cmd = read_le16(header + 1);
        uint32_t rec_len = read_le32(header + 3);
        unsigned char version = header[7];

        if (version != config.protocol_version)
        {
            log_message(LOG_WARN, "handle_data_client: 协议版本不匹配 (sock=%d)", data_client_sock);
            break;
        }

        char *recv_data = NULL;
        if (rec_len > 0)
        {
            recv_data = (char *)malloc(rec_len + 1);
            if (!recv_data)
            {
                log_message(LOG_ERROR, "handle_data_client: malloc失败 (sock=%d)", data_client_sock);
                break;
            }

            ssize_t n2 = recv_all(data_client_sock, recv_data, rec_len);
            if (n2 <= 0 || (uint32_t)n2 != rec_len)
            {
                log_message(LOG_ERROR, "handle_data_client: recv data失败 or 不完整 (sock=%d)", data_client_sock);
                free(recv_data);
                break;
            }
            recv_data[rec_len] = '\0';
        }

        cJSON *req_json = NULL;
        if (recv_data)
        {
            req_json = cJSON_Parse(recv_data);
            if (!req_json)
            {
                log_message(LOG_WARN, "handle_data_client: JSON解析失败 (sock=%d)", data_client_sock);
                free(recv_data);
                break;
            }
        }
        else
        {
            req_json = cJSON_CreateObject();
        }

        cJSON *req_login_id = cJSON_GetObjectItemCaseSensitive(req_json, "LoginID");
        if (!cJSON_IsString(req_login_id) || strcmp(req_login_id->valuestring, token_plus) != 0)
        {
            log_message(LOG_WARN, "handle_data_client: LoginID不匹配 (sock=%d)", data_client_sock);
            cJSON_Delete(req_json);
            if (recv_data)
                free(recv_data);
            break;
        }

        char *resp_data = NULL;
        uint32_t resp_data_len = 0;
        if (handle_request(cmd, recv_data, rec_len, conn_mysql, &resp_data, &resp_data_len, token_plus) < 0)
        {
            log_message(LOG_WARN, "handle_data_client: 处理请求失败 cmd=0x%04X (sock=%d)", cmd, data_client_sock);
            cJSON_Delete(req_json);
            if (recv_data)
                free(recv_data);
            break;
        }

        if (resp_data)
        {
            unsigned char resp_header[8];
            resp_header[0] = 0xFF;
            write_le16(resp_header + 1, cmd + 1);
            write_le32(resp_header + 3, resp_data_len);
            resp_header[7] = (unsigned char)config.protocol_version;

            size_t total_len = 8 + resp_data_len;
            unsigned char *send_buf = (unsigned char *)malloc(total_len);
            if (send_buf)
            {
                memcpy(send_buf, resp_header, 8);
                memcpy(send_buf + 8, resp_data, resp_data_len);

                ssize_t sent = send_all(data_client_sock, send_buf, total_len);
                if (sent != (ssize_t)total_len)
                {
                    log_message(LOG_ERROR, "handle_data_client: 发送响应失败 (sock=%d)", data_client_sock);
                    free(send_buf);
                    free(resp_data);
                    cJSON_Delete(req_json);
                    if (recv_data)
                        free(recv_data);
                    break;
                }

                free(send_buf);
            }
            free(resp_data);

            log_message(LOG_INFO, "handle_data_client: 已发送响应 cmd=0x%04X (sock=%d)", cmd + 1, data_client_sock);
        }

        cJSON_Delete(req_json);
        if (recv_data)
            free(recv_data);

        usleep(500000);
    }

    mysql_close(conn_mysql);
    close(data_client_sock);
    log_message(LOG_INFO, "handle_data_client: 关闭 (token=%s)", token_plus);
    pthread_exit(NULL);
}