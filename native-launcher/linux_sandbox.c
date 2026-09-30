#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <sched.h>
#include <seccomp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_landlock_create_ruleset
#error "Landlock syscall numbers are required"
#endif

#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#define LANDLOCK_RULE_PATH_BENEATH 1
#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#define LANDLOCK_ACCESS_FS_RESOLVE_UNIX (1ULL << 16)
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#define LANDLOCK_ACCESS_NET_BIND_UDP (1ULL << 2)
#define LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP (1ULL << 3)
#define LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET (1ULL << 0)
#define LANDLOCK_SCOPE_SIGNAL (1ULL << 1)

struct ll_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
    uint64_t scoped;
};

struct ll_path_beneath_attr {
    uint64_t allowed_access;
    int32_t parent_fd;
};

static void fail(const char *operation) {
    dprintf(STDERR_FILENO, "native Linux sandbox failed at %s: %s\n",
            operation, strerror(errno));
    _exit(70);
}

static void write_text(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        fail(path);
    }
    size_t remaining = strlen(value);
    const char *cursor = value;
    while (remaining > 0) {
        ssize_t written = write(fd, cursor, remaining);
        if (written < 0) {
            close(fd);
            fail(path);
        }
        cursor += written;
        remaining -= (size_t)written;
    }
    if (close(fd) != 0) {
        fail(path);
    }
}

static void configure_user_namespace(void) {
    if (geteuid() != 0 || getegid() != 0) {
        errno = EPERM;
        fail("require trusted root launcher");
    }
    if (setgroups(0, NULL) != 0) {
        fail("clear supplementary groups");
    }

    int child_ready[2];
    int maps_ready[2];
    if (pipe2(child_ready, O_CLOEXEC) != 0 ||
        pipe2(maps_ready, O_CLOEXEC) != 0) {
        fail("create user namespace mapping pipes");
    }
    pid_t namespace_pid = getpid();
    pid_t mapper = fork();
    if (mapper < 0) {
        fail("fork user namespace mapper");
    }
    if (mapper == 0) {
        close(child_ready[1]);
        close(maps_ready[0]);
        char ready = 0;
        if (read(child_ready[0], &ready, 1) != 1 || ready != '1') {
            fail("wait for user namespace");
        }
        close(child_ready[0]);

        char path[64];
        if (snprintf(path, sizeof(path), "/proc/%d/setgroups",
                     namespace_pid) < 0) {
            fail("format setgroups path");
        }
        write_text(path, "deny\n");
        if (snprintf(path, sizeof(path), "/proc/%d/uid_map",
                     namespace_pid) < 0) {
            fail("format uid map path");
        }
        write_text(path, "0 0 1\n65534 65534 1\n");
        if (snprintf(path, sizeof(path), "/proc/%d/gid_map",
                     namespace_pid) < 0) {
            fail("format gid map path");
        }
        write_text(path, "0 0 1\n65534 65534 1\n");
        if (write(maps_ready[1], "1", 1) != 1) {
            fail("signal user namespace mappings");
        }
        close(maps_ready[1]);
        _exit(0);
    }

    close(child_ready[0]);
    close(maps_ready[1]);
    if (unshare(CLONE_NEWUSER) != 0) {
        fail("unshare user namespace");
    }
    if (write(child_ready[1], "1", 1) != 1) {
        fail("signal user namespace creation");
    }
    close(child_ready[1]);
    char mapped = 0;
    if (read(maps_ready[0], &mapped, 1) != 1 || mapped != '1') {
        fail("receive user namespace mappings");
    }
    close(maps_ready[0]);
    int mapper_status = 0;
    if (waitpid(mapper, &mapper_status, 0) != mapper ||
        !WIFEXITED(mapper_status) || WEXITSTATUS(mapper_status) != 0) {
        errno = EPROTO;
        fail("user namespace mapper");
    }
}

static void configure_namespaces(void) {
    configure_user_namespace();
    if (unshare(CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS |
                CLONE_NEWPID) != 0) {
        fail("unshare runtime namespaces");
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        fail("make mount tree private");
    }
    if (sethostname("gov-worker", 10) != 0) {
        fail("set isolated hostname");
    }
}

static void configure_child_mounts(void) {
    if (umount2("/proc", MNT_DETACH) != 0 && errno != EINVAL && errno != ENOENT) {
        fail("detach host proc");
    }
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC,
              NULL) != 0) {
        fail("mount private proc");
    }
    if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV,
              "size=16m,mode=0700,uid=65534,gid=65534") != 0) {
        fail("mount private tmp");
    }
    if (mount("tmpfs", "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
              "size=16m,mode=0700,uid=65534,gid=65534") != 0) {
        fail("mount private shm");
    }
}

static int add_landlock_path(int ruleset_fd, const char *path,
                             uint64_t allowed_access) {
    int path_fd = open(path, O_PATH | O_CLOEXEC);
    if (path_fd < 0) {
        return -1;
    }
    struct ll_path_beneath_attr rule = {
        .allowed_access = allowed_access,
        .parent_fd = path_fd,
    };
    int result = (int)syscall(SYS_landlock_add_rule, ruleset_fd,
                              LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
    int saved = errno;
    close(path_fd);
    errno = saved;
    return result;
}

static int add_landlock_fd(int ruleset_fd, int path_fd,
                           uint64_t allowed_access) {
    struct ll_path_beneath_attr rule = {
        .allowed_access = allowed_access,
        .parent_fd = path_fd,
    };
    return (int)syscall(SYS_landlock_add_rule, ruleset_fd,
                        LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
}

static void configure_landlock(int worker_fd) {
    int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0,
                           LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 6) {
        errno = abi < 0 ? errno : ENOTSUP;
        fail("require Landlock ABI 6 or newer");
    }

    uint64_t handled_fs = LANDLOCK_ACCESS_FS_EXECUTE |
        LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
        LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |
        LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE |
        LANDLOCK_ACCESS_FS_IOCTL_DEV;
    if (abi >= 9) {
        handled_fs |= LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
    }
    uint64_t handled_net = LANDLOCK_ACCESS_NET_BIND_TCP |
        LANDLOCK_ACCESS_NET_CONNECT_TCP;
    if (abi >= 10) {
        handled_net |= LANDLOCK_ACCESS_NET_BIND_UDP |
            LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP;
    }
    struct ll_ruleset_attr ruleset = {
        .handled_access_fs = handled_fs,
        .handled_access_net = handled_net,
        .scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL,
    };
    int ruleset_fd = (int)syscall(SYS_landlock_create_ruleset, &ruleset,
                                  sizeof(ruleset), 0);
    if (ruleset_fd < 0) {
        fail("create Landlock ruleset");
    }
    if (add_landlock_fd(ruleset_fd, worker_fd,
                        LANDLOCK_ACCESS_FS_EXECUTE |
                        LANDLOCK_ACCESS_FS_READ_FILE) != 0) {
        close(ruleset_fd);
        fail("allow worker executable");
    }
    uint64_t private_access = handled_fs & ~LANDLOCK_ACCESS_FS_EXECUTE;
    if (add_landlock_path(ruleset_fd, "/tmp", private_access) != 0 ||
        add_landlock_path(ruleset_fd, "/dev/shm", private_access) != 0 ||
        add_landlock_path(ruleset_fd, "/proc/self/ns",
                          LANDLOCK_ACCESS_FS_READ_FILE |
                          LANDLOCK_ACCESS_FS_READ_DIR) != 0) {
        close(ruleset_fd);
        fail("add Landlock path rule");
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        close(ruleset_fd);
        fail("set no_new_privs");
    }
    if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) != 0) {
        close(ruleset_fd);
        fail("enforce Landlock ruleset");
    }
    close(ruleset_fd);
}

static void add_seccomp_denial(scmp_filter_ctx context, const char *name) {
    int syscall_number = seccomp_syscall_resolve_name(name);
    if (syscall_number == __NR_SCMP_ERROR) {
        return;
    }
    if (seccomp_rule_add(context, SCMP_ACT_ERRNO(EPERM), syscall_number, 0) != 0) {
        errno = EINVAL;
        fail("add seccomp rule");
    }
}

static void configure_seccomp(void) {
    static const char *denied[] = {
        "acct", "add_key", "bpf", "chroot", "clone", "clone3",
        "delete_module", "finit_module", "fork", "init_module", "ioperm",
        "iopl", "io_uring_setup", "kcmp", "keyctl", "kexec_file_load",
        "kexec_load", "mount", "move_mount", "name_to_handle_at",
        "open_by_handle_at", "open_tree", "perf_event_open", "pivot_root",
        "process_vm_readv", "process_vm_writev", "ptrace", "quotactl",
        "reboot", "request_key", "setns", "swapon", "swapoff", "umount2",
        "unshare", "userfaultfd", "vfork",
    };
    scmp_filter_ctx context = seccomp_init(SCMP_ACT_ALLOW);
    if (context == NULL) {
        errno = ENOMEM;
        fail("create seccomp filter");
    }
    for (size_t index = 0; index < sizeof(denied) / sizeof(denied[0]); index++) {
        add_seccomp_denial(context, denied[index]);
    }
    if (seccomp_load(context) != 0) {
        seccomp_release(context);
        fail("load seccomp filter");
    }
    seccomp_release(context);
}

static void drop_privileges(void) {
    for (int capability = 0; capability <= CAP_LAST_CAP; capability++) {
        if (prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 && errno != EINVAL) {
            fail("drop capability bounding set");
        }
    }
    if (setresgid(65534, 65534, 65534) != 0 ||
        setresuid(65534, 65534, 65534) != 0) {
        fail("drop worker uid and gid");
    }
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[2] = {{0}};
    if (syscall(SYS_capset, &header, &data) != 0) {
        fail("clear process capabilities");
    }
}

static void close_untrusted_descriptors(void) {
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 4U, ~0U, 0U) == 0) {
        return;
    }
    if (errno != ENOSYS) {
        fail("close inherited descriptors");
    }
#endif
    long limit = sysconf(_SC_OPEN_MAX);
    if (limit < 0 || limit > 1048576) {
        limit = 65536;
    }
    for (int fd = 4; fd < limit; fd++) {
        close(fd);
    }
}

static int preopen_ready_file(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                  0600);
    if (fd < 0) {
        fail("create readiness record");
    }
    return fd;
}

static void write_ready_file(int fd, pid_t child_pid) {
    if (dprintf(fd, "%d\n", child_pid) < 0 || fsync(fd) != 0) {
        close(fd);
        fail("write readiness record");
    }
    if (close(fd) != 0) {
        fail("close readiness record");
    }
}

static void usage(void) {
    dprintf(STDERR_FILENO,
            "usage: native-linux-launcher --worker PATH --control-fd FD --ready-file PATH\n");
    _exit(64);
}

int main(int argc, char **argv) {
    const char *worker = NULL;
    const char *ready_file = NULL;
    int control_fd = -1;
    if (argc != 7) {
        usage();
    }
    for (int index = 1; index < argc; index += 2) {
        if (strcmp(argv[index], "--worker") == 0) {
            worker = argv[index + 1];
        } else if (strcmp(argv[index], "--control-fd") == 0) {
            char *end = NULL;
            long parsed = strtol(argv[index + 1], &end, 10);
            if (end == NULL || *end != '\0' || parsed < 3 || parsed > 1048576) {
                usage();
            }
            control_fd = (int)parsed;
        } else if (strcmp(argv[index], "--ready-file") == 0) {
            ready_file = argv[index + 1];
        } else {
            usage();
        }
    }
    if (worker == NULL || ready_file == NULL || control_fd < 3 || worker[0] != '/' ||
        ready_file[0] != '/') {
        usage();
    }

    char release = 0;
    if (read(control_fd, &release, 1) != 1 || release != '1') {
        fail("cgroup release handshake");
    }
    close(control_fd);
    int opened_worker = open(worker, O_PATH | O_CLOEXEC);
    if (opened_worker < 0) {
        fail("preopen hostile worker");
    }
    int worker_fd = 3;
    if (opened_worker != worker_fd) {
        if (dup3(opened_worker, worker_fd, O_CLOEXEC) != worker_fd) {
            fail("stabilize hostile worker descriptor");
        }
        close(opened_worker);
    }
    int ready_file_fd = preopen_ready_file(ready_file);
    configure_namespaces();

    int ready_pipe[2];
    if (pipe2(ready_pipe, O_CLOEXEC) != 0) {
        fail("create sandbox readiness pipe");
    }
    pid_t child = fork();
    if (child < 0) {
        fail("fork PID namespace child");
    }
    if (child == 0) {
        close(ready_pipe[0]);
        close(ready_file_fd);
        configure_child_mounts();
        configure_landlock(worker_fd);
        drop_privileges();
        configure_seccomp();
        if (write(ready_pipe[1], "1", 1) != 1) {
            fail("signal sandbox readiness");
        }
        close(ready_pipe[1]);
        close_untrusted_descriptors();
        char *const worker_argv[] = {(char *)worker, NULL};
        char *const worker_env[] = {"HOME=/tmp", "PATH=/usr/bin:/bin", NULL};
        execveat(worker_fd, "", worker_argv, worker_env, AT_EMPTY_PATH);
        fail("exec hostile worker");
    }

    close(ready_pipe[1]);
    char child_ready = 0;
    ssize_t ready_count = read(ready_pipe[0], &child_ready, 1);
    close(ready_pipe[0]);
    if (ready_count != 1 || child_ready != '1') {
        close(ready_file_fd);
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        errno = EPROTO;
        fail("child sandbox setup");
    }
    write_ready_file(ready_file_fd, child);

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        fail("wait for hostile worker");
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 70;
}
