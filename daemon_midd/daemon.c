#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#define CONFIG_FILE "daemon.conf"
#define MAX_PATH 512

static volatile sig_atomic_t running = 1;

// 信号处理：终止主循环
void signal_handler(int signo) {
    if (signo == SIGTERM || signo == SIGINT) {
        running = 0;
    }
}

// 将进程变为守护进程
void daemonize() {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        // 父进程退出
        exit(EXIT_SUCCESS);
    }

    // 创建新会话
    if (setsid() < 0) {
        perror("setsid");
        exit(EXIT_FAILURE);
    }

    // 第二次 fork，防止重新获得控制终端
    pid = fork();
    if (pid < 0) {
        perror("fork2");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // 修改文件权限掩码
    umask(0);

    // 注意：不改变工作目录，以便支持相对路径
    // chdir("/");   // 我们故意注释掉，保留原目录

    // 关闭标准文件描述符，重定向到 /dev/null
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) close(fd);
    }
}

// 从配置文件读取 program 键的值
// 格式：program=路径
// 返回 0 成功，-1 失败
int read_config(const char *config_file, char *program, size_t size, int *interval) {
    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        perror("fopen config");
        return -1;
    }

    char line[256];
    int found_program = 0;
    // interval 默认值
    *interval = 1;

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#')
            continue;

        char *key = strtok(line, "=");
        char *value = strtok(NULL, "");
        if (key && value) {
            // 去除前后空格
            while (*key == ' ' || *key == '\t') key++;
            size_t len = strlen(key);
            while (len > 0 && (key[len-1] == ' ' || key[len-1] == '\t')) {
                key[--len] = '\0';
            }

            while (*value == ' ' || *value == '\t') value++;
            len = strlen(value);
            while (len > 0 && (value[len-1] == ' ' || value[len-1] == '\t')) {
                value[--len] = '\0';
            }

            if (strcmp(key, "program") == 0) {
                strncpy(program, value, size - 1);
                program[size - 1] = '\0';
                found_program = 1;
            } else if (strcmp(key, "interval") == 0) {
                int val = atoi(value);
                if (val > 0) {
                    *interval = val;
                }
            }
        }
    }

    fclose(fp);
    return found_program ? 0 : -1;
}

// 检查 program 是否正在运行（通过 pidof 命令）
int is_running(const char *program) {
    char cmd[MAX_PATH + 50];
    snprintf(cmd, sizeof(cmd), "pidof -x '%s' > /dev/null 2>&1", program);

    int ret = system(cmd);
    // system 返回：-1 出错，127 shell 不可用，否则是命令的退出状态
    if (ret == -1) {
        return 0;   // 无法判断，假设未运行
    }
    // pidof 成功找到进程返回 0，否则返回非0
    return (WIFEXITED(ret) && WEXITSTATUS(ret) == 0);
}

// 启动程序（非阻塞，fork 子进程执行）
void start_program(const char *program) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork for start");
        return;
    }
    if (pid == 0) {
        // 子进程：执行目标程序
        // 使用 execlp 可以在 PATH 中查找，但传入的 program 可能是相对路径
        execlp(program, program, (char *)NULL);
        // 如果 exec 失败
        perror("execlp");
        _exit(EXIT_FAILURE);
    }
    // 父进程忽略子进程结束信号（已在 main 中设置），直接返回
}

int main(int argc, char *argv[]) {
    char config_file[MAX_PATH] = CONFIG_FILE;
    if (argc > 1) {
        strncpy(config_file, argv[1], MAX_PATH - 1);
        config_file[MAX_PATH - 1] = '\0';
    }

    char program[MAX_PATH] = {0};
    int check_interval = 1;   // 默认 1 秒
    if (read_config(config_file, program, sizeof(program), &check_interval) != 0) {
        fprintf(stderr, "Failed to read config from '%s'\n", config_file);
        exit(EXIT_FAILURE);
    }

    printf("Daemon will monitor: %s (check every %d sec)\n", program, check_interval);

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGCHLD, SIG_IGN);

    daemonize();

    while (running) {
        if (!is_running(program)) {
            start_program(program);
        }
        sleep(check_interval);
    }

    return 0;
}