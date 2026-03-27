#include "common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif

static volatile sig_atomic_t g_stop = 0;

/*
 * Attack target: attacker_bias tampers this variable in gateway memory.
 */
volatile double g_latest_measurement = 0.0;
volatile uint64_t g_latest_seq = 0;

static void on_sigint(int signo) {
    (void)signo;
    g_stop = 1;
}

static int env_int(const char *name, int def_val) {
    const char *val = getenv(name);
    if (!val || val[0] == '\0') {
        return def_val;
    }
    int v = atoi(val);
    return (v > 0) ? v : def_val;
}

static const char *env_str(const char *name, const char *def_val) {
    const char *val = getenv(name);
    if (!val || val[0] == '\0') {
        return def_val;
    }
    return val;
}

static void timespec_add_ms(struct timespec *ts, int ms) {
    if (ms <= 0) {
        return;
    }
    ts->tv_sec += ms / 1000;
    ts->tv_nsec += (long)(ms % 1000) * 1000000L;
    while (ts->tv_nsec >= 1000000000L) {
        ts->tv_sec += 1;
        ts->tv_nsec -= 1000000000L;
    }
}

static int timespec_cmp(const struct timespec *a, const struct timespec *b) {
    if (a->tv_sec != b->tv_sec) {
        return (a->tv_sec > b->tv_sec) ? 1 : -1;
    }
    if (a->tv_nsec != b->tv_nsec) {
        return (a->tv_nsec > b->tv_nsec) ? 1 : -1;
    }
    return 0;
}

static long long timespec_delta_ms(const struct timespec *from, const struct timespec *to) {
    long long sec = (long long)to->tv_sec - (long long)from->tv_sec;
    long long nsec = (long long)to->tv_nsec - (long long)from->tv_nsec;
    return sec * 1000LL + nsec / 1000000LL;
}

static int read_period_file(const char *path, int current_ms) {
    if (!path || path[0] == '\0') {
        return current_ms;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return current_ms;
    }

    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        return current_ms;
    }
    buf[n] = '\0';

    int v = atoi(buf);
    if (v <= 0) {
        return current_ms;
    }
    return v;
}

static int dump_meta_file(const char *path, int listen_port, const char *host_ip, int host_port) {
    if (!path || path[0] == '\0') {
        return 0;
    }

    FILE *fp = fopen(path, "w");
    if (!fp) {
        perror("fopen meta file");
        return -1;
    }

    fprintf(fp, "status=ready\n");
    fprintf(fp, "pid=%d\n", getpid());
    fprintf(fp, "listen_port=%d\n", listen_port);
    fprintf(fp, "host_ip=%s\n", host_ip);
    fprintf(fp, "host_port=%d\n", host_port);
    fclose(fp);
    return 0;
}

static int env_is_true(const char *name) {
    const char *val = getenv(name);
    if (!val || val[0] == '\0') {
        return 0;
    }
    return strcmp(val, "1") == 0 || strcasecmp(val, "true") == 0 || strcasecmp(val, "yes") == 0;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [listen_port] [host_ip] [host_port] [send_period_ms]\n"
            "Defaults: listen_port=%d host_ip=%s host_port=%d send_period_ms=100\n",
            prog, RPI_INGEST_PORT, SENSOR_IP, SENSOR_PORT);
}

int main(int argc, char **argv) {
    int listen_port = env_int("CPS_RPI_LISTEN_PORT", RPI_INGEST_PORT);
    const char *host_ip = env_str("CPS_HOST_IP", SENSOR_IP);
    int host_port = env_int("CPS_HOST_PORT", SENSOR_PORT);
    int send_period_ms = env_int("CPS_SEND_PERIOD_MS", 100);
    const char *period_file = getenv("CPS_PERIOD_FILE");
    const char *meta_path = getenv("CPS_GATEWAY_META_FILE");

    if (argc > 1) {
        listen_port = atoi(argv[1]);
    }
    if (argc > 2) {
        host_ip = argv[2];
    }
    if (argc > 3) {
        host_port = atoi(argv[3]);
    }
    if (argc > 4) {
        send_period_ms = atoi(argv[4]);
    }

    if (listen_port <= 0 || host_port <= 0 || send_period_ms <= 0) {
        usage(argv[0]);
        return 1;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

#if defined(__linux__) && defined(PR_SET_NAME)
    (void)prctl(PR_SET_NAME, "gateway", 0L, 0L, 0L);
#endif
#if defined(__linux__) && defined(PR_SET_DUMPABLE)
    if (prctl(PR_SET_DUMPABLE, 1L, 0L, 0L, 0L) != 0) {
        perror("prctl(PR_SET_DUMPABLE)");
    }
#endif
#if defined(__linux__) && defined(PR_SET_PTRACER) && defined(PR_SET_PTRACER_ANY)
    if (env_is_true("CPS_PTRACE_COMPAT")) {
        if (prctl(PR_SET_PTRACER, (unsigned long)PR_SET_PTRACER_ANY, 0L, 0L, 0L) != 0) {
            perror("prctl(PR_SET_PTRACER)");
        }
    }
#endif

    int recv_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_sock < 0) {
        perror("socket(recv_sock)");
        return 1;
    }

    int reuse = 1;
    if (setsockopt(recv_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR)");
        close(recv_sock);
        return 1;
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = htons((uint16_t)listen_port);
    if (bind(recv_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind(recv_sock)");
        close(recv_sock);
        return 1;
    }

    int send_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_sock < 0) {
        perror("socket(send_sock)");
        close(recv_sock);
        return 1;
    }

    struct sockaddr_in host_addr;
    memset(&host_addr, 0, sizeof(host_addr));
    host_addr.sin_family = AF_INET;
    host_addr.sin_port = htons((uint16_t)host_port);
    if (inet_pton(AF_INET, host_ip, &host_addr.sin_addr) != 1) {
        fprintf(stderr, "inet_pton failed for host_ip=%s\n", host_ip);
        close(send_sock);
        close(recv_sock);
        return 1;
    }

    if (dump_meta_file(meta_path, listen_port, host_ip, host_port) == 0 && meta_path && meta_path[0] != '\0') {
        printf("[gateway] metadata written to %s\n", meta_path);
    }

    printf("[gateway] pid=%d listen=0.0.0.0:%d host=%s:%d send_period_ms=%d\n",
           getpid(), listen_port, host_ip, host_port, send_period_ms);
    if (period_file && period_file[0] != '\0') {
        printf("[gateway] period control file: %s\n", period_file);
    }
    fflush(stdout);

    struct timespec next_send;
    (void)clock_gettime(CLOCK_MONOTONIC, &next_send);
    timespec_add_ms(&next_send, send_period_ms);

    double latest_incoming = 0.0;
    int has_sample = 0;

    char buf[256];
    while (!g_stop) {
        int updated_period = read_period_file(period_file, send_period_ms);
        if (updated_period != send_period_ms) {
            send_period_ms = updated_period;
            (void)clock_gettime(CLOCK_MONOTONIC, &next_send);
            timespec_add_ms(&next_send, send_period_ms);
            printf("[gateway] send_period_ms updated to %d via period file\n", send_period_ms);
            fflush(stdout);
        }

        struct timespec now;
        (void)clock_gettime(CLOCK_MONOTONIC, &now);

        long long ms_until_send = 200;
        if (has_sample) {
            ms_until_send = timespec_delta_ms(&now, &next_send);
            if (ms_until_send < 0) {
                ms_until_send = 0;
            }
            if (ms_until_send > 200) {
                ms_until_send = 200;
            }
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(recv_sock, &rfds);

        struct timeval tv;
        tv.tv_sec = (int)(ms_until_send / 1000);
        tv.tv_usec = (int)(ms_until_send % 1000) * 1000;

        int sel = select(recv_sock + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select");
            break;
        }

        if (sel > 0 && FD_ISSET(recv_sock, &rfds)) {
            struct sockaddr_storage src_addr;
            socklen_t src_len = sizeof(src_addr);
            ssize_t r = recvfrom(recv_sock, buf, sizeof(buf) - 1, 0,
                                 (struct sockaddr *)&src_addr, &src_len);
            if (r < 0) {
                if (errno == EINTR) {
                    continue;
                }
                perror("recvfrom");
                break;
            }
            buf[r] = '\0';

            unsigned long long seq_ull = 0;
            double incoming = 0.0;
            if (sscanf(buf, "%llu %lf", &seq_ull, &incoming) != 2) {
                fprintf(stderr, "[gateway] parse error: %s\n", buf);
                continue;
            }

            g_latest_seq = (uint64_t)seq_ull;
            g_latest_measurement = incoming;
            latest_incoming = incoming;
            has_sample = 1;

            printf("[gateway] recv seq=%llu v2=%.6f\n",
                   (unsigned long long)g_latest_seq, latest_incoming);
            fflush(stdout);
        }

        (void)clock_gettime(CLOCK_MONOTONIC, &now);
        if (has_sample && timespec_cmp(&now, &next_send) >= 0) {
            double used = g_latest_measurement;
            char out[128];
            int n = snprintf(out, sizeof(out), "%llu %.6f",
                             (unsigned long long)g_latest_seq, used);
            if (n < 0 || n >= (int)sizeof(out)) {
                fprintf(stderr, "[gateway] snprintf overflow\n");
                break;
            }

            if (sendto(send_sock, out, (size_t)n, 0,
                       (struct sockaddr *)&host_addr, sizeof(host_addr)) < 0) {
                perror("sendto(host)");
                break;
            }

            double diff = used - latest_incoming;
            if (fabs(diff) > 1e-9) {
                printf("[gateway] send seq=%llu v2=%.6f bias=%.6f  <-- memory tamper\n",
                       (unsigned long long)g_latest_seq, used, diff);
            } else {
                printf("[gateway] send seq=%llu v2=%.6f\n",
                       (unsigned long long)g_latest_seq, used);
            }
            fflush(stdout);

            next_send = now;
            timespec_add_ms(&next_send, send_period_ms);
        }
    }

    close(send_sock);
    close(recv_sock);
    printf("[gateway] stopped.\n");
    return 0;
}
