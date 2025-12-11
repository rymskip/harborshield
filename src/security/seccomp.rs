use super::error::{Result, SecurityError};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch, apply_filter};
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

#[allow(dead_code)]
mod syscalls {
    // Process control
    pub const READ: i64 = 0;
    pub const WRITE: i64 = 1;
    pub const OPEN: i64 = 2;
    pub const CLOSE: i64 = 3;
    pub const STAT: i64 = 4;
    pub const FSTAT: i64 = 5;
    pub const LSTAT: i64 = 6;
    pub const POLL: i64 = 7;
    pub const LSEEK: i64 = 8;
    pub const MMAP: i64 = 9;
    pub const MPROTECT: i64 = 10;
    pub const MUNMAP: i64 = 11;
    pub const BRK: i64 = 12;
    pub const RT_SIGACTION: i64 = 13;
    pub const RT_SIGPROCMASK: i64 = 14;
    pub const RT_SIGRETURN: i64 = 15;
    pub const IOCTL: i64 = 16;
    pub const PREAD64: i64 = 17;
    pub const PWRITE64: i64 = 18;
    pub const READV: i64 = 19;
    pub const WRITEV: i64 = 20;
    pub const ACCESS: i64 = 21;
    pub const PIPE: i64 = 22;
    pub const SELECT: i64 = 23;
    pub const SCHED_YIELD: i64 = 24;
    pub const MREMAP: i64 = 25;
    pub const MSYNC: i64 = 26;
    pub const MINCORE: i64 = 27;
    pub const MADVISE: i64 = 28;
    pub const SHMGET: i64 = 29;
    pub const SHMAT: i64 = 30;
    pub const SHMCTL: i64 = 31;
    pub const DUP: i64 = 32;
    pub const DUP2: i64 = 33;
    pub const PAUSE: i64 = 34;
    pub const NANOSLEEP: i64 = 35;
    pub const GETITIMER: i64 = 36;
    pub const ALARM: i64 = 37;
    pub const SETITIMER: i64 = 38;
    pub const GETPID: i64 = 39;
    pub const SENDFILE: i64 = 40;
    pub const SOCKET: i64 = 41;
    pub const CONNECT: i64 = 42;
    pub const ACCEPT: i64 = 43;
    pub const SENDTO: i64 = 44;
    pub const RECVFROM: i64 = 45;
    pub const SENDMSG: i64 = 46;
    pub const RECVMSG: i64 = 47;
    pub const SHUTDOWN: i64 = 48;
    pub const BIND: i64 = 49;
    pub const LISTEN: i64 = 50;
    pub const GETSOCKNAME: i64 = 51;
    pub const GETPEERNAME: i64 = 52;
    pub const SOCKETPAIR: i64 = 53;
    pub const SETSOCKOPT: i64 = 54;
    pub const GETSOCKOPT: i64 = 55;
    pub const CLONE: i64 = 56;
    pub const FORK: i64 = 57;
    pub const VFORK: i64 = 58;
    pub const EXECVE: i64 = 59;
    pub const EXIT: i64 = 60;
    pub const WAIT4: i64 = 61;
    pub const KILL: i64 = 62;
    pub const UNAME: i64 = 63;
    pub const SEMGET: i64 = 64;
    pub const SEMOP: i64 = 65;
    pub const SEMCTL: i64 = 66;
    pub const SHMDT: i64 = 67;
    pub const MSGGET: i64 = 68;
    pub const MSGSND: i64 = 69;
    pub const MSGRCV: i64 = 70;
    pub const MSGCTL: i64 = 71;
    pub const FCNTL: i64 = 72;
    pub const FLOCK: i64 = 73;
    pub const FSYNC: i64 = 74;
    pub const FDATASYNC: i64 = 75;
    pub const TRUNCATE: i64 = 76;
    pub const FTRUNCATE: i64 = 77;
    pub const GETDENTS: i64 = 78;
    pub const GETCWD: i64 = 79;
    pub const CHDIR: i64 = 80;
    pub const FCHDIR: i64 = 81;
    pub const RENAME: i64 = 82;
    pub const MKDIR: i64 = 83;
    pub const RMDIR: i64 = 84;
    pub const CREAT: i64 = 85;
    pub const LINK: i64 = 86;
    pub const UNLINK: i64 = 87;
    pub const SYMLINK: i64 = 88;
    pub const READLINK: i64 = 89;
    pub const CHMOD: i64 = 90;
    pub const FCHMOD: i64 = 91;
    pub const CHOWN: i64 = 92;
    pub const FCHOWN: i64 = 93;
    pub const LCHOWN: i64 = 94;
    pub const UMASK: i64 = 95;
    pub const GETTIMEOFDAY: i64 = 96;
    pub const GETRLIMIT: i64 = 97;
    pub const GETRUSAGE: i64 = 98;
    pub const SYSINFO: i64 = 99;
    pub const TIMES: i64 = 100;
    pub const PTRACE: i64 = 101;
    pub const GETUID: i64 = 102;
    pub const SYSLOG: i64 = 103;
    pub const GETGID: i64 = 104;
    pub const SETUID: i64 = 105;
    pub const SETGID: i64 = 106;
    pub const GETEUID: i64 = 107;
    pub const GETEGID: i64 = 108;
    pub const SETPGID: i64 = 109;
    pub const GETPPID: i64 = 110;
    pub const GETPGRP: i64 = 111;
    pub const SETSID: i64 = 112;
    pub const SETREUID: i64 = 113;
    pub const SETREGID: i64 = 114;
    pub const GETGROUPS: i64 = 115;
    pub const SETGROUPS: i64 = 116;
    pub const SETRESUID: i64 = 117;
    pub const GETRESUID: i64 = 118;
    pub const SETRESGID: i64 = 119;
    pub const GETRESGID: i64 = 120;
    pub const GETPGID: i64 = 121;
    pub const SETFSUID: i64 = 122;
    pub const SETFSGID: i64 = 123;
    pub const GETSID: i64 = 124;
    pub const CAPGET: i64 = 125;
    pub const CAPSET: i64 = 126;
    pub const RT_SIGPENDING: i64 = 127;
    pub const RT_SIGTIMEDWAIT: i64 = 128;
    pub const RT_SIGQUEUEINFO: i64 = 129;
    pub const RT_SIGSUSPEND: i64 = 130;
    pub const SIGALTSTACK: i64 = 131;
    pub const UTIME: i64 = 132;
    pub const MKNOD: i64 = 133;
    pub const USELIB: i64 = 134;
    pub const PERSONALITY: i64 = 135;
    pub const USTAT: i64 = 136;
    pub const STATFS: i64 = 137;
    pub const FSTATFS: i64 = 138;
    pub const SYSFS: i64 = 139;
    pub const GETPRIORITY: i64 = 140;
    pub const SETPRIORITY: i64 = 141;
    pub const SCHED_SETPARAM: i64 = 142;
    pub const SCHED_GETPARAM: i64 = 143;
    pub const SCHED_SETSCHEDULER: i64 = 144;
    pub const SCHED_GETSCHEDULER: i64 = 145;
    pub const SCHED_GET_PRIORITY_MAX: i64 = 146;
    pub const SCHED_GET_PRIORITY_MIN: i64 = 147;
    pub const SCHED_RR_GET_INTERVAL: i64 = 148;
    pub const MLOCK: i64 = 149;
    pub const MUNLOCK: i64 = 150;
    pub const MLOCKALL: i64 = 151;
    pub const MUNLOCKALL: i64 = 152;
    pub const VHANGUP: i64 = 153;
    pub const MODIFY_LDT: i64 = 154;
    pub const PIVOT_ROOT: i64 = 155;
    pub const _SYSCTL: i64 = 156;
    pub const PRCTL: i64 = 157;
    pub const ARCH_PRCTL: i64 = 158;
    pub const ADJTIMEX: i64 = 159;
    pub const SETRLIMIT: i64 = 160;
    pub const CHROOT: i64 = 161;
    pub const SYNC: i64 = 162;
    pub const ACCT: i64 = 163;
    pub const SETTIMEOFDAY: i64 = 164;
    pub const MOUNT: i64 = 165;
    pub const UMOUNT2: i64 = 166;
    pub const SWAPON: i64 = 167;
    pub const SWAPOFF: i64 = 168;
    pub const REBOOT: i64 = 169;
    pub const SETHOSTNAME: i64 = 170;
    pub const SETDOMAINNAME: i64 = 171;
    pub const IOPL: i64 = 172;
    pub const IOPERM: i64 = 173;
    pub const CREATE_MODULE: i64 = 174;
    pub const INIT_MODULE: i64 = 175;
    pub const DELETE_MODULE: i64 = 176;
    pub const GET_KERNEL_SYMS: i64 = 177;
    pub const QUERY_MODULE: i64 = 178;
    pub const QUOTACTL: i64 = 179;
    pub const NFSSERVCTL: i64 = 180;
    pub const GETPMSG: i64 = 181;
    pub const PUTPMSG: i64 = 182;
    pub const AFS_SYSCALL: i64 = 183;
    pub const TUXCALL: i64 = 184;
    pub const SECURITY: i64 = 185;
    pub const GETTID: i64 = 186;
    pub const READAHEAD: i64 = 187;
    pub const SETXATTR: i64 = 188;
    pub const LSETXATTR: i64 = 189;
    pub const FSETXATTR: i64 = 190;
    pub const GETXATTR: i64 = 191;
    pub const LGETXATTR: i64 = 192;
    pub const FGETXATTR: i64 = 193;
    pub const LISTXATTR: i64 = 194;
    pub const LLISTXATTR: i64 = 195;
    pub const FLISTXATTR: i64 = 196;
    pub const REMOVEXATTR: i64 = 197;
    pub const LREMOVEXATTR: i64 = 198;
    pub const FREMOVEXATTR: i64 = 199;
    pub const TKILL: i64 = 200;
    pub const TIME: i64 = 201;
    pub const FUTEX: i64 = 202;
    pub const SCHED_SETAFFINITY: i64 = 203;
    pub const SCHED_GETAFFINITY: i64 = 204;
    pub const SET_THREAD_AREA: i64 = 205;
    pub const IO_SETUP: i64 = 206;
    pub const IO_DESTROY: i64 = 207;
    pub const IO_GETEVENTS: i64 = 208;
    pub const IO_SUBMIT: i64 = 209;
    pub const IO_CANCEL: i64 = 210;
    pub const GET_THREAD_AREA: i64 = 211;
    pub const LOOKUP_DCOOKIE: i64 = 212;
    pub const EPOLL_CREATE: i64 = 213;
    pub const EPOLL_CTL_OLD: i64 = 214;
    pub const EPOLL_WAIT_OLD: i64 = 215;
    pub const REMAP_FILE_PAGES: i64 = 216;
    pub const GETDENTS64: i64 = 217;
    pub const SET_TID_ADDRESS: i64 = 218;
    pub const RESTART_SYSCALL: i64 = 219;
    pub const SEMTIMEDOP: i64 = 220;
    pub const FADVISE64: i64 = 221;
    pub const TIMER_CREATE: i64 = 222;
    pub const TIMER_SETTIME: i64 = 223;
    pub const TIMER_GETTIME: i64 = 224;
    pub const TIMER_GETOVERRUN: i64 = 225;
    pub const TIMER_DELETE: i64 = 226;
    pub const CLOCK_SETTIME: i64 = 227;
    pub const CLOCK_GETTIME: i64 = 228;
    pub const CLOCK_GETRES: i64 = 229;
    pub const CLOCK_NANOSLEEP: i64 = 230;
    pub const EXIT_GROUP: i64 = 231;
    pub const EPOLL_WAIT: i64 = 232;
    pub const EPOLL_CTL: i64 = 233;
    pub const TGKILL: i64 = 234;
    pub const UTIMES: i64 = 235;
    pub const VSERVER: i64 = 236;
    pub const MBIND: i64 = 237;
    pub const SET_MEMPOLICY: i64 = 238;
    pub const GET_MEMPOLICY: i64 = 239;
    pub const MQ_OPEN: i64 = 240;
    pub const MQ_UNLINK: i64 = 241;
    pub const MQ_TIMEDSEND: i64 = 242;
    pub const MQ_TIMEDRECEIVE: i64 = 243;
    pub const MQ_NOTIFY: i64 = 244;
    pub const MQ_GETSETATTR: i64 = 245;
    pub const KEXEC_LOAD: i64 = 246;
    pub const WAITID: i64 = 247;
    pub const ADD_KEY: i64 = 248;
    pub const REQUEST_KEY: i64 = 249;
    pub const KEYCTL: i64 = 250;
    pub const IOPRIO_SET: i64 = 251;
    pub const IOPRIO_GET: i64 = 252;
    pub const INOTIFY_INIT: i64 = 253;
    pub const INOTIFY_ADD_WATCH: i64 = 254;
    pub const INOTIFY_RM_WATCH: i64 = 255;
    pub const MIGRATE_PAGES: i64 = 256;
    pub const OPENAT: i64 = 257;
    pub const MKDIRAT: i64 = 258;
    pub const MKNODAT: i64 = 259;
    pub const FCHOWNAT: i64 = 260;
    pub const FUTIMESAT: i64 = 261;
    pub const NEWFSTATAT: i64 = 262;
    pub const UNLINKAT: i64 = 263;
    pub const RENAMEAT: i64 = 264;
    pub const LINKAT: i64 = 265;
    pub const SYMLINKAT: i64 = 266;
    pub const READLINKAT: i64 = 267;
    pub const FCHMODAT: i64 = 268;
    pub const FACCESSAT: i64 = 269;
    pub const PSELECT6: i64 = 270;
    pub const PPOLL: i64 = 271;
    pub const UNSHARE: i64 = 272;
    pub const SET_ROBUST_LIST: i64 = 273;
    pub const GET_ROBUST_LIST: i64 = 274;
    pub const SPLICE: i64 = 275;
    pub const TEE: i64 = 276;
    pub const SYNC_FILE_RANGE: i64 = 277;
    pub const VMSPLICE: i64 = 278;
    pub const MOVE_PAGES: i64 = 279;
    pub const UTIMENSAT: i64 = 280;
    pub const EPOLL_PWAIT: i64 = 281;
    pub const SIGNALFD: i64 = 282;
    pub const TIMERFD_CREATE: i64 = 283;
    pub const EVENTFD: i64 = 284;
    pub const FALLOCATE: i64 = 285;
    pub const TIMERFD_SETTIME: i64 = 286;
    pub const TIMERFD_GETTIME: i64 = 287;
    pub const ACCEPT4: i64 = 288;
    pub const SIGNALFD4: i64 = 289;
    pub const EVENTFD2: i64 = 290;
    pub const EPOLL_CREATE1: i64 = 291;
    pub const DUP3: i64 = 292;
    pub const PIPE2: i64 = 293;
    pub const INOTIFY_INIT1: i64 = 294;
    pub const PREADV: i64 = 295;
    pub const PWRITEV: i64 = 296;
    pub const RT_TGSIGQUEUEINFO: i64 = 297;
    pub const PERF_EVENT_OPEN: i64 = 298;
    pub const RECVMMSG: i64 = 299;
    pub const FANOTIFY_INIT: i64 = 300;
    pub const FANOTIFY_MARK: i64 = 301;
    pub const PRLIMIT64: i64 = 302;
    pub const NAME_TO_HANDLE_AT: i64 = 303;
    pub const OPEN_BY_HANDLE_AT: i64 = 304;
    pub const CLOCK_ADJTIME: i64 = 305;
    pub const SYNCFS: i64 = 306;
    pub const SENDMMSG: i64 = 307;
    pub const SETNS: i64 = 308;
    pub const GETCPU: i64 = 309;
    pub const PROCESS_VM_READV: i64 = 310;
    pub const PROCESS_VM_WRITEV: i64 = 311;
    pub const KCMP: i64 = 312;
    pub const FINIT_MODULE: i64 = 313;
    pub const SCHED_SETATTR: i64 = 314;
    pub const SCHED_GETATTR: i64 = 315;
    pub const RENAMEAT2: i64 = 316;
    pub const SECCOMP: i64 = 317;
    pub const GETRANDOM: i64 = 318;
    pub const MEMFD_CREATE: i64 = 319;
    pub const KEXEC_FILE_LOAD: i64 = 320;
    pub const BPF: i64 = 321;
    pub const EXECVEAT: i64 = 322;
    pub const USERFAULTFD: i64 = 323;
    pub const MEMBARRIER: i64 = 324;
    pub const MLOCK2: i64 = 325;
    pub const COPY_FILE_RANGE: i64 = 326;
    pub const PREADV2: i64 = 327;
    pub const PWRITEV2: i64 = 328;
    pub const PKEY_MPROTECT: i64 = 329;
    pub const PKEY_ALLOC: i64 = 330;
    pub const PKEY_FREE: i64 = 331;
    pub const STATX: i64 = 332;
    pub const IO_PGETEVENTS: i64 = 333;
    pub const RSEQ: i64 = 334;
    pub const PIDFD_SEND_SIGNAL: i64 = 424;
    pub const IO_URING_SETUP: i64 = 425;
    pub const IO_URING_ENTER: i64 = 426;
    pub const IO_URING_REGISTER: i64 = 427;
    pub const OPEN_TREE: i64 = 428;
    pub const MOVE_MOUNT: i64 = 429;
    pub const FSOPEN: i64 = 430;
    pub const FSCONFIG: i64 = 431;
    pub const FSMOUNT: i64 = 432;
    pub const FSPICK: i64 = 433;
    pub const PIDFD_OPEN: i64 = 434;
    pub const CLONE3: i64 = 435;
}

pub fn apply_seccomp_filters() -> Result<()> {
    if cfg!(not(target_arch = "x86_64")) {
        warn!("Seccomp filters are only implemented for x86_64");
        return Ok(());
    }

    let mut rules = BTreeMap::new();

    // Essential syscalls for basic operation
    let essential_syscalls = vec![
        syscalls::READ,
        syscalls::WRITE,
        syscalls::OPEN,
        syscalls::OPENAT,
        syscalls::CLOSE,
        syscalls::STAT,
        syscalls::FSTAT,
        syscalls::LSTAT,
        syscalls::NEWFSTATAT,
        syscalls::POLL,
        syscalls::PPOLL,
        syscalls::LSEEK,
        syscalls::MMAP,
        syscalls::MPROTECT,
        syscalls::MUNMAP,
        syscalls::BRK,
        syscalls::RT_SIGACTION,
        syscalls::RT_SIGPROCMASK,
        syscalls::RT_SIGRETURN,
        syscalls::PREAD64,
        syscalls::PWRITE64,
        syscalls::READV,
        syscalls::PREADV,
        syscalls::WRITEV,
        syscalls::PWRITEV,
        syscalls::ACCESS,
        syscalls::FACCESSAT,
        syscalls::PIPE,
        syscalls::PIPE2,
        syscalls::SELECT,
        syscalls::PSELECT6,
        syscalls::SCHED_YIELD,
        syscalls::MREMAP,
        syscalls::MSYNC,
        syscalls::MINCORE,
        syscalls::MADVISE,
        syscalls::DUP,
        syscalls::DUP2,
        syscalls::DUP3,
        syscalls::NANOSLEEP,
        syscalls::CLOCK_NANOSLEEP,
        syscalls::GETITIMER,
        syscalls::SETITIMER,
        syscalls::GETPID,
        syscalls::GETTID,
        syscalls::GETPPID,
        syscalls::GETUID,
        syscalls::GETGID,
        syscalls::GETEUID,
        syscalls::GETEGID,
        syscalls::GETPGRP,
        syscalls::GETPGID,
        syscalls::GETSID,
        syscalls::GETGROUPS,
        syscalls::FCNTL,
        syscalls::FLOCK,
        syscalls::FSYNC,
        syscalls::FDATASYNC,
        syscalls::FTRUNCATE,
        syscalls::GETDENTS,
        syscalls::GETDENTS64,
        syscalls::GETCWD,
        syscalls::CHDIR,
        syscalls::FCHDIR,
        syscalls::READLINK,
        syscalls::READLINKAT,
        syscalls::UMASK,
        syscalls::GETTIMEOFDAY,
        syscalls::GETRLIMIT,
        syscalls::PRLIMIT64,
        syscalls::GETRUSAGE,
        syscalls::SYSINFO,
        syscalls::TIMES,
        syscalls::PRCTL,
        syscalls::ARCH_PRCTL,
        syscalls::SET_TID_ADDRESS,
        syscalls::SET_ROBUST_LIST,
        syscalls::GET_ROBUST_LIST,
        syscalls::FUTEX,
        syscalls::SCHED_GETAFFINITY,
        syscalls::SCHED_SETAFFINITY,
        syscalls::CLOCK_GETTIME,
        syscalls::CLOCK_GETRES,
        syscalls::EXIT,
        syscalls::EXIT_GROUP,
        syscalls::WAITID,
        syscalls::WAIT4,
        syscalls::UNAME,
        syscalls::SEMGET,
        syscalls::SEMOP,
        syscalls::SEMCTL,
        syscalls::SEMTIMEDOP,
        syscalls::MSGGET,
        syscalls::MSGSND,
        syscalls::MSGRCV,
        syscalls::MSGCTL,
        syscalls::GETXATTR,
        syscalls::LGETXATTR,
        syscalls::FGETXATTR,
        syscalls::LISTXATTR,
        syscalls::LLISTXATTR,
        syscalls::FLISTXATTR,
        syscalls::STATX,
        syscalls::GETRANDOM,
        syscalls::MEMBARRIER,
        syscalls::RSEQ,
        syscalls::RESTART_SYSCALL,
    ];

    // Network-related syscalls for container firewall
    let network_syscalls = vec![
        syscalls::SOCKET,
        syscalls::CONNECT,
        syscalls::ACCEPT,
        syscalls::ACCEPT4,
        syscalls::SENDTO,
        syscalls::RECVFROM,
        syscalls::SENDMSG,
        syscalls::SENDMMSG,
        syscalls::RECVMSG,
        syscalls::RECVMMSG,
        syscalls::SHUTDOWN,
        syscalls::BIND,
        syscalls::LISTEN,
        syscalls::GETSOCKNAME,
        syscalls::GETPEERNAME,
        syscalls::SOCKETPAIR,
        syscalls::SETSOCKOPT,
        syscalls::GETSOCKOPT,
    ];

    // File system operations needed for configuration and logging
    let filesystem_syscalls = vec![
        syscalls::RENAME,
        syscalls::RENAMEAT,
        syscalls::RENAMEAT2,
        syscalls::MKDIR,
        syscalls::MKDIRAT,
        syscalls::RMDIR,
        syscalls::UNLINK,
        syscalls::UNLINKAT,
        syscalls::SYMLINK,
        syscalls::SYMLINKAT,
        syscalls::LINK,
        syscalls::LINKAT,
        syscalls::CHMOD,
        syscalls::FCHMOD,
        syscalls::FCHMODAT,
        syscalls::CHOWN,
        syscalls::FCHOWN,
        syscalls::FCHOWNAT,
        syscalls::LCHOWN,
        syscalls::TRUNCATE,
        syscalls::UTIME,
        syscalls::UTIMES,
        syscalls::UTIMENSAT,
        syscalls::FUTIMESAT,
        syscalls::STATFS,
        syscalls::FSTATFS,
        syscalls::FALLOCATE,
        syscalls::SYNC_FILE_RANGE,
        syscalls::SYNCFS,
        syscalls::SENDFILE,
    ];

    // Epoll and event handling for async I/O
    let event_syscalls = vec![
        syscalls::EPOLL_CREATE,
        syscalls::EPOLL_CREATE1,
        syscalls::EPOLL_CTL,
        syscalls::EPOLL_CTL_OLD,
        syscalls::EPOLL_WAIT,
        syscalls::EPOLL_WAIT_OLD,
        syscalls::EPOLL_PWAIT,
        syscalls::EVENTFD,
        syscalls::EVENTFD2,
        syscalls::SIGNALFD,
        syscalls::SIGNALFD4,
        syscalls::TIMERFD_CREATE,
        syscalls::TIMERFD_SETTIME,
        syscalls::TIMERFD_GETTIME,
    ];

    // Process and thread management (limited)
    let process_syscalls = vec![
        syscalls::CLONE,
        syscalls::EXECVE,
        syscalls::EXECVEAT,
        syscalls::KILL,
        syscalls::TKILL,
        syscalls::TGKILL,
        syscalls::RT_SIGQUEUEINFO,
        syscalls::RT_TGSIGQUEUEINFO,
        syscalls::SIGALTSTACK,
        syscalls::RT_SIGPENDING,
        syscalls::RT_SIGTIMEDWAIT,
        syscalls::RT_SIGSUSPEND,
        syscalls::PAUSE,
        syscalls::ALARM,
        syscalls::SETPGID,
        syscalls::GETPRIORITY,
        syscalls::SETPRIORITY,
        syscalls::SCHED_SETPARAM,
        syscalls::SCHED_GETPARAM,
        syscalls::SCHED_SETSCHEDULER,
        syscalls::SCHED_GETSCHEDULER,
        syscalls::SCHED_GET_PRIORITY_MAX,
        syscalls::SCHED_GET_PRIORITY_MIN,
        syscalls::SCHED_RR_GET_INTERVAL,
        syscalls::SCHED_SETATTR,
        syscalls::SCHED_GETATTR,
    ];

    // Memory management
    let memory_syscalls = vec![
        syscalls::SHMGET,
        syscalls::SHMAT,
        syscalls::SHMCTL,
        syscalls::SHMDT,
        syscalls::MLOCK,
        syscalls::MUNLOCK,
        syscalls::MLOCKALL,
        syscalls::MUNLOCKALL,
        syscalls::MLOCK2,
        syscalls::MBIND,
        syscalls::SET_MEMPOLICY,
        syscalls::GET_MEMPOLICY,
        syscalls::MIGRATE_PAGES,
        syscalls::MOVE_PAGES,
    ];

    // I/O operations
    let io_syscalls = vec![
        syscalls::IOCTL,
        syscalls::IO_SETUP,
        syscalls::IO_DESTROY,
        syscalls::IO_GETEVENTS,
        syscalls::IO_SUBMIT,
        syscalls::IO_CANCEL,
        syscalls::IO_PGETEVENTS,
        syscalls::SPLICE,
        syscalls::TEE,
        syscalls::VMSPLICE,
        syscalls::COPY_FILE_RANGE,
        syscalls::PREADV2,
        syscalls::PWRITEV2,
    ];

    // Time-related syscalls
    let time_syscalls = vec![
        syscalls::TIME,
        syscalls::CLOCK_SETTIME,
        syscalls::CLOCK_ADJTIME,
        syscalls::ADJTIMEX,
        syscalls::SETTIMEOFDAY,
        syscalls::TIMER_CREATE,
        syscalls::TIMER_SETTIME,
        syscalls::TIMER_GETTIME,
        syscalls::TIMER_GETOVERRUN,
        syscalls::TIMER_DELETE,
    ];

    // Extended attributes (may be needed for Docker)
    let xattr_syscalls = vec![
        syscalls::SETXATTR,
        syscalls::LSETXATTR,
        syscalls::FSETXATTR,
        syscalls::REMOVEXATTR,
        syscalls::LREMOVEXATTR,
        syscalls::FREMOVEXATTR,
    ];

    // Add all allowed syscalls to rules
    for &syscall in essential_syscalls
        .iter()
        .chain(network_syscalls.iter())
        .chain(filesystem_syscalls.iter())
        .chain(event_syscalls.iter())
        .chain(process_syscalls.iter())
        .chain(memory_syscalls.iter())
        .chain(io_syscalls.iter())
        .chain(time_syscalls.iter())
        .chain(xattr_syscalls.iter())
    {
        rules.insert(syscall, vec![]);
    }

    // Explicitly denied syscalls (dangerous operations)
    let denied_syscalls = vec![
        syscalls::KEXEC_LOAD,
        syscalls::KEXEC_FILE_LOAD,
        syscalls::INIT_MODULE,
        syscalls::FINIT_MODULE,
        syscalls::DELETE_MODULE,
        syscalls::CREATE_MODULE,
        syscalls::QUERY_MODULE,
        syscalls::MEMFD_CREATE,
        syscalls::USERFAULTFD,
        syscalls::PERF_EVENT_OPEN,
        syscalls::BPF,
        syscalls::MOUNT,
        syscalls::UMOUNT2,
        syscalls::SWAPON,
        syscalls::SWAPOFF,
        syscalls::REBOOT,
        syscalls::PIVOT_ROOT,
        syscalls::CHROOT,
        syscalls::ACCT,
        syscalls::SETHOSTNAME,
        syscalls::SETDOMAINNAME,
        syscalls::IOPL,
        syscalls::IOPERM,
        syscalls::MODIFY_LDT,
        syscalls::SYSLOG,
        syscalls::VHANGUP,
        syscalls::_SYSCTL,
        syscalls::PTRACE,
        syscalls::PROCESS_VM_READV,
        syscalls::PROCESS_VM_WRITEV,
        syscalls::KCMP,
        syscalls::USELIB,
        syscalls::PERSONALITY,
        syscalls::USTAT,
        syscalls::SYSFS,
        syscalls::QUOTACTL,
        syscalls::NFSSERVCTL,
        syscalls::GETPMSG,
        syscalls::PUTPMSG,
        syscalls::AFS_SYSCALL,
        syscalls::TUXCALL,
        syscalls::SECURITY,
        syscalls::LOOKUP_DCOOKIE,
        syscalls::REMAP_FILE_PAGES,
        syscalls::VSERVER,
        syscalls::MQ_OPEN,
        syscalls::MQ_UNLINK,
        syscalls::MQ_TIMEDSEND,
        syscalls::MQ_TIMEDRECEIVE,
        syscalls::MQ_NOTIFY,
        syscalls::MQ_GETSETATTR,
        syscalls::ADD_KEY,
        syscalls::REQUEST_KEY,
        syscalls::KEYCTL,
        syscalls::IOPRIO_SET,
        syscalls::IOPRIO_GET,
        syscalls::INOTIFY_INIT,
        syscalls::INOTIFY_INIT1,
        syscalls::INOTIFY_ADD_WATCH,
        syscalls::INOTIFY_RM_WATCH,
        syscalls::FANOTIFY_INIT,
        syscalls::FANOTIFY_MARK,
        syscalls::NAME_TO_HANDLE_AT,
        syscalls::OPEN_BY_HANDLE_AT,
        syscalls::SETNS,
        syscalls::UNSHARE,
        syscalls::SECCOMP,
        syscalls::PKEY_MPROTECT,
        syscalls::PKEY_ALLOC,
        syscalls::PKEY_FREE,
        syscalls::IO_URING_SETUP,
        syscalls::IO_URING_ENTER,
        syscalls::IO_URING_REGISTER,
        syscalls::OPEN_TREE,
        syscalls::MOVE_MOUNT,
        syscalls::FSOPEN,
        syscalls::FSCONFIG,
        syscalls::FSMOUNT,
        syscalls::FSPICK,
        syscalls::PIDFD_SEND_SIGNAL,
        syscalls::PIDFD_OPEN,
        syscalls::CLONE3,
        syscalls::SETUID,
        syscalls::SETGID,
        syscalls::SETREUID,
        syscalls::SETREGID,
        syscalls::SETRESUID,
        syscalls::SETRESGID,
        syscalls::SETGROUPS,
        syscalls::SETFSUID,
        syscalls::SETFSGID,
        syscalls::CAPGET,
        syscalls::CAPSET,
        syscalls::SETRLIMIT,
        syscalls::SETSID,
        syscalls::MKNOD,
        syscalls::MKNODAT,
    ];

    // Log denied syscalls for debugging
    debug!("Denying {} dangerous syscalls", denied_syscalls.len());
    for &syscall in &denied_syscalls {
        debug!(
            "Denying syscall: {} ({})",
            syscall,
            get_syscall_name(syscall)
        );
    }

    // Create the filter with logging for denied syscalls
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Log, // Log denied syscalls instead of killing immediately
        SeccompAction::Allow,
        TargetArch::x86_64,
    )
    .map_err(|e| {
        SecurityError::seccomp(format!("Failed to create seccomp filter: {}", e), Some(e))
    })?;

    // Compile to BPF
    let bpf_program: BpfProgram = filter.try_into().map_err(|e| {
        SecurityError::seccomp(format!("Failed to compile seccomp filter: {}", e), Some(e))
    })?;

    // Apply the filter
    apply_filter(&bpf_program).map_err(|e| {
        SecurityError::ApplicationFailed(format!("Failed to apply seccomp filter: {}", e))
    })?;

    info!("Applied comprehensive seccomp filters");

    Ok(())
}

#[allow(dead_code)]
pub fn apply_strict_seccomp_filters() -> Result<()> {
    if cfg!(not(target_arch = "x86_64")) {
        warn!("Seccomp filters are only implemented for x86_64");
        return Ok(());
    }

    let mut rules = BTreeMap::new();

    // For strict mode, only allow the minimal set of syscalls needed
    let allowed_syscalls = vec![
        // Essential for basic operation
        syscalls::READ,
        syscalls::WRITE,
        syscalls::OPEN,
        syscalls::OPENAT,
        syscalls::CLOSE,
        syscalls::STAT,
        syscalls::FSTAT,
        syscalls::LSTAT,
        syscalls::NEWFSTATAT,
        syscalls::POLL,
        syscalls::PPOLL,
        syscalls::LSEEK,
        syscalls::MMAP,
        syscalls::MPROTECT,
        syscalls::MUNMAP,
        syscalls::BRK,
        syscalls::RT_SIGACTION,
        syscalls::RT_SIGPROCMASK,
        syscalls::RT_SIGRETURN,
        syscalls::PREAD64,
        syscalls::PWRITE64,
        syscalls::READV,
        syscalls::WRITEV,
        syscalls::ACCESS,
        syscalls::FACCESSAT,
        syscalls::PIPE,
        syscalls::PIPE2,
        syscalls::SELECT,
        syscalls::PSELECT6,
        syscalls::SCHED_YIELD,
        syscalls::NANOSLEEP,
        syscalls::CLOCK_NANOSLEEP,
        syscalls::GETPID,
        syscalls::GETTID,
        syscalls::GETPPID,
        syscalls::GETUID,
        syscalls::GETGID,
        syscalls::GETEUID,
        syscalls::GETEGID,
        syscalls::FCNTL,
        syscalls::FLOCK,
        syscalls::FSYNC,
        syscalls::FDATASYNC,
        syscalls::FTRUNCATE,
        syscalls::GETDENTS,
        syscalls::GETDENTS64,
        syscalls::GETCWD,
        syscalls::UMASK,
        syscalls::GETTIMEOFDAY,
        syscalls::GETRLIMIT,
        syscalls::PRLIMIT64,
        syscalls::PRCTL,
        syscalls::ARCH_PRCTL,
        syscalls::SET_TID_ADDRESS,
        syscalls::SET_ROBUST_LIST,
        syscalls::GET_ROBUST_LIST,
        syscalls::FUTEX,
        syscalls::CLOCK_GETTIME,
        syscalls::CLOCK_GETRES,
        syscalls::EXIT,
        syscalls::EXIT_GROUP,
        syscalls::UNAME,
        syscalls::GETRANDOM,
        syscalls::MEMBARRIER,
        syscalls::RESTART_SYSCALL,
        // Network operations for firewall
        syscalls::SOCKET,
        syscalls::CONNECT,
        syscalls::ACCEPT,
        syscalls::ACCEPT4,
        syscalls::SENDTO,
        syscalls::RECVFROM,
        syscalls::SENDMSG,
        syscalls::RECVMSG,
        syscalls::SHUTDOWN,
        syscalls::BIND,
        syscalls::LISTEN,
        syscalls::GETSOCKNAME,
        syscalls::GETPEERNAME,
        syscalls::SETSOCKOPT,
        syscalls::GETSOCKOPT,
        // Epoll for async I/O
        syscalls::EPOLL_CREATE1,
        syscalls::EPOLL_CTL,
        syscalls::EPOLL_WAIT,
        syscalls::EPOLL_PWAIT,
        // Signal handling
        syscalls::SIGALTSTACK,
        syscalls::RT_SIGPENDING,
        syscalls::RT_SIGTIMEDWAIT,
        syscalls::RT_SIGSUSPEND,
        // Basic file operations
        syscalls::DUP,
        syscalls::DUP2,
        syscalls::DUP3,
        syscalls::IOCTL,
    ];

    for &syscall in &allowed_syscalls {
        rules.insert(syscall, vec![]);
    }

    // Use KillProcess for strict enforcement
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        TargetArch::x86_64,
    )
    .map_err(|e| {
        SecurityError::seccomp(
            format!("Failed to create strict seccomp filter: {}", e),
            Some(e),
        )
    })?;

    // Compile to BPF
    let bpf_program: BpfProgram = filter.try_into().map_err(|e| {
        SecurityError::seccomp(
            format!("Failed to compile strict seccomp filter: {}", e),
            Some(e),
        )
    })?;

    // Apply the filter
    apply_filter(&bpf_program).map_err(|e| {
        SecurityError::ApplicationFailed(format!("Failed to apply strict seccomp filter: {}", e))
    })?;

    info!("Applied strict seccomp filters (production mode)");

    Ok(())
}

fn get_syscall_name(syscall: i64) -> &'static str {
    match syscall {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        6 => "lstat",
        7 => "poll",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        13 => "rt_sigaction",
        14 => "rt_sigprocmask",
        15 => "rt_sigreturn",
        16 => "ioctl",
        17 => "pread64",
        18 => "pwrite64",
        19 => "readv",
        20 => "writev",
        21 => "access",
        22 => "pipe",
        23 => "select",
        24 => "sched_yield",
        25 => "mremap",
        26 => "msync",
        27 => "mincore",
        28 => "madvise",
        29 => "shmget",
        30 => "shmat",
        31 => "shmctl",
        32 => "dup",
        33 => "dup2",
        34 => "pause",
        35 => "nanosleep",
        36 => "getitimer",
        37 => "alarm",
        38 => "setitimer",
        39 => "getpid",
        40 => "sendfile",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        48 => "shutdown",
        49 => "bind",
        50 => "listen",
        51 => "getsockname",
        52 => "getpeername",
        53 => "socketpair",
        54 => "setsockopt",
        55 => "getsockopt",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        61 => "wait4",
        62 => "kill",
        63 => "uname",
        64 => "semget",
        65 => "semop",
        66 => "semctl",
        67 => "shmdt",
        68 => "msgget",
        69 => "msgsnd",
        70 => "msgrcv",
        71 => "msgctl",
        72 => "fcntl",
        73 => "flock",
        74 => "fsync",
        75 => "fdatasync",
        76 => "truncate",
        77 => "ftruncate",
        78 => "getdents",
        79 => "getcwd",
        80 => "chdir",
        81 => "fchdir",
        82 => "rename",
        83 => "mkdir",
        84 => "rmdir",
        85 => "creat",
        86 => "link",
        87 => "unlink",
        88 => "symlink",
        89 => "readlink",
        90 => "chmod",
        91 => "fchmod",
        92 => "chown",
        93 => "fchown",
        94 => "lchown",
        95 => "umask",
        96 => "gettimeofday",
        97 => "getrlimit",
        98 => "getrusage",
        99 => "sysinfo",
        100 => "times",
        101 => "ptrace",
        102 => "getuid",
        103 => "syslog",
        104 => "getgid",
        105 => "setuid",
        106 => "setgid",
        107 => "geteuid",
        108 => "getegid",
        109 => "setpgid",
        110 => "getppid",
        111 => "getpgrp",
        112 => "setsid",
        113 => "setreuid",
        114 => "setregid",
        115 => "getgroups",
        116 => "setgroups",
        117 => "setresuid",
        118 => "getresuid",
        119 => "setresgid",
        120 => "getresgid",
        121 => "getpgid",
        122 => "setfsuid",
        123 => "setfsgid",
        124 => "getsid",
        125 => "capget",
        126 => "capset",
        127 => "rt_sigpending",
        128 => "rt_sigtimedwait",
        129 => "rt_sigqueueinfo",
        130 => "rt_sigsuspend",
        131 => "sigaltstack",
        132 => "utime",
        133 => "mknod",
        134 => "uselib",
        135 => "personality",
        136 => "ustat",
        137 => "statfs",
        138 => "fstatfs",
        139 => "sysfs",
        140 => "getpriority",
        141 => "setpriority",
        142 => "sched_setparam",
        143 => "sched_getparam",
        144 => "sched_setscheduler",
        145 => "sched_getscheduler",
        146 => "sched_get_priority_max",
        147 => "sched_get_priority_min",
        148 => "sched_rr_get_interval",
        149 => "mlock",
        150 => "munlock",
        151 => "mlockall",
        152 => "munlockall",
        153 => "vhangup",
        154 => "modify_ldt",
        155 => "pivot_root",
        156 => "_sysctl",
        157 => "prctl",
        158 => "arch_prctl",
        159 => "adjtimex",
        160 => "setrlimit",
        161 => "chroot",
        162 => "sync",
        163 => "acct",
        164 => "settimeofday",
        165 => "mount",
        166 => "umount2",
        167 => "swapon",
        168 => "swapoff",
        169 => "reboot",
        170 => "sethostname",
        171 => "setdomainname",
        172 => "iopl",
        173 => "ioperm",
        174 => "create_module",
        175 => "init_module",
        176 => "delete_module",
        177 => "get_kernel_syms",
        178 => "query_module",
        179 => "quotactl",
        180 => "nfsservctl",
        181 => "getpmsg",
        182 => "putpmsg",
        183 => "afs_syscall",
        184 => "tuxcall",
        185 => "security",
        186 => "gettid",
        187 => "readahead",
        188 => "setxattr",
        189 => "lsetxattr",
        190 => "fsetxattr",
        191 => "getxattr",
        192 => "lgetxattr",
        193 => "fgetxattr",
        194 => "listxattr",
        195 => "llistxattr",
        196 => "flistxattr",
        197 => "removexattr",
        198 => "lremovexattr",
        199 => "fremovexattr",
        200 => "tkill",
        201 => "time",
        202 => "futex",
        203 => "sched_setaffinity",
        204 => "sched_getaffinity",
        205 => "set_thread_area",
        206 => "io_setup",
        207 => "io_destroy",
        208 => "io_getevents",
        209 => "io_submit",
        210 => "io_cancel",
        211 => "get_thread_area",
        212 => "lookup_dcookie",
        213 => "epoll_create",
        214 => "epoll_ctl_old",
        215 => "epoll_wait_old",
        216 => "remap_file_pages",
        217 => "getdents64",
        218 => "set_tid_address",
        219 => "restart_syscall",
        220 => "semtimedop",
        221 => "fadvise64",
        222 => "timer_create",
        223 => "timer_settime",
        224 => "timer_gettime",
        225 => "timer_getoverrun",
        226 => "timer_delete",
        227 => "clock_settime",
        228 => "clock_gettime",
        229 => "clock_getres",
        230 => "clock_nanosleep",
        231 => "exit_group",
        232 => "epoll_wait",
        233 => "epoll_ctl",
        234 => "tgkill",
        235 => "utimes",
        236 => "vserver",
        237 => "mbind",
        238 => "set_mempolicy",
        239 => "get_mempolicy",
        240 => "mq_open",
        241 => "mq_unlink",
        242 => "mq_timedsend",
        243 => "mq_timedreceive",
        244 => "mq_notify",
        245 => "mq_getsetattr",
        246 => "kexec_load",
        247 => "waitid",
        248 => "add_key",
        249 => "request_key",
        250 => "keyctl",
        251 => "ioprio_set",
        252 => "ioprio_get",
        253 => "inotify_init",
        254 => "inotify_add_watch",
        255 => "inotify_rm_watch",
        256 => "migrate_pages",
        257 => "openat",
        258 => "mkdirat",
        259 => "mknodat",
        260 => "fchownat",
        261 => "futimesat",
        262 => "newfstatat",
        263 => "unlinkat",
        264 => "renameat",
        265 => "linkat",
        266 => "symlinkat",
        267 => "readlinkat",
        268 => "fchmodat",
        269 => "faccessat",
        270 => "pselect6",
        271 => "ppoll",
        272 => "unshare",
        273 => "set_robust_list",
        274 => "get_robust_list",
        275 => "splice",
        276 => "tee",
        277 => "sync_file_range",
        278 => "vmsplice",
        279 => "move_pages",
        280 => "utimensat",
        281 => "epoll_pwait",
        282 => "signalfd",
        283 => "timerfd_create",
        284 => "eventfd",
        285 => "fallocate",
        286 => "timerfd_settime",
        287 => "timerfd_gettime",
        288 => "accept4",
        289 => "signalfd4",
        290 => "eventfd2",
        291 => "epoll_create1",
        292 => "dup3",
        293 => "pipe2",
        294 => "inotify_init1",
        295 => "preadv",
        296 => "pwritev",
        297 => "rt_tgsigqueueinfo",
        298 => "perf_event_open",
        299 => "recvmmsg",
        300 => "fanotify_init",
        301 => "fanotify_mark",
        302 => "prlimit64",
        303 => "name_to_handle_at",
        304 => "open_by_handle_at",
        305 => "clock_adjtime",
        306 => "syncfs",
        307 => "sendmmsg",
        308 => "setns",
        309 => "getcpu",
        310 => "process_vm_readv",
        311 => "process_vm_writev",
        312 => "kcmp",
        313 => "finit_module",
        314 => "sched_setattr",
        315 => "sched_getattr",
        316 => "renameat2",
        317 => "seccomp",
        318 => "getrandom",
        319 => "memfd_create",
        320 => "kexec_file_load",
        321 => "bpf",
        322 => "execveat",
        323 => "userfaultfd",
        324 => "membarrier",
        325 => "mlock2",
        326 => "copy_file_range",
        327 => "preadv2",
        328 => "pwritev2",
        329 => "pkey_mprotect",
        330 => "pkey_alloc",
        331 => "pkey_free",
        332 => "statx",
        333 => "io_pgetevents",
        334 => "rseq",
        424 => "pidfd_send_signal",
        425 => "io_uring_setup",
        426 => "io_uring_enter",
        427 => "io_uring_register",
        428 => "open_tree",
        429 => "move_mount",
        430 => "fsopen",
        431 => "fsconfig",
        432 => "fsmount",
        433 => "fspick",
        434 => "pidfd_open",
        435 => "clone3",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_syscall_name_read() {
        assert_eq!(get_syscall_name(syscalls::READ), "read");
    }

    #[test]
    fn test_get_syscall_name_write() {
        assert_eq!(get_syscall_name(syscalls::WRITE), "write");
    }

    #[test]
    fn test_get_syscall_name_open() {
        assert_eq!(get_syscall_name(syscalls::OPEN), "open");
    }

    #[test]
    fn test_get_syscall_name_close() {
        assert_eq!(get_syscall_name(syscalls::CLOSE), "close");
    }

    #[test]
    fn test_get_syscall_name_socket() {
        assert_eq!(get_syscall_name(syscalls::SOCKET), "socket");
    }

    #[test]
    fn test_get_syscall_name_clone() {
        assert_eq!(get_syscall_name(syscalls::CLONE), "clone");
    }

    #[test]
    fn test_get_syscall_name_execve() {
        assert_eq!(get_syscall_name(syscalls::EXECVE), "execve");
    }

    #[test]
    fn test_get_syscall_name_exit() {
        assert_eq!(get_syscall_name(syscalls::EXIT), "exit");
    }

    #[test]
    fn test_get_syscall_name_epoll_create1() {
        assert_eq!(get_syscall_name(syscalls::EPOLL_CREATE1), "epoll_create1");
    }

    #[test]
    fn test_get_syscall_name_getrandom() {
        assert_eq!(get_syscall_name(syscalls::GETRANDOM), "getrandom");
    }

    #[test]
    fn test_get_syscall_name_clone3() {
        assert_eq!(get_syscall_name(syscalls::CLONE3), "clone3");
    }

    #[test]
    fn test_get_syscall_name_unknown() {
        assert_eq!(get_syscall_name(99999), "unknown");
    }

    #[test]
    fn test_get_syscall_name_negative() {
        assert_eq!(get_syscall_name(-1), "unknown");
    }

    #[test]
    fn test_syscall_constants_basic() {
        // Verify some basic syscall number constants
        assert_eq!(syscalls::READ, 0);
        assert_eq!(syscalls::WRITE, 1);
        assert_eq!(syscalls::OPEN, 2);
        assert_eq!(syscalls::CLOSE, 3);
    }

    #[test]
    fn test_syscall_constants_network() {
        // Verify network syscall constants
        assert_eq!(syscalls::SOCKET, 41);
        assert_eq!(syscalls::CONNECT, 42);
        assert_eq!(syscalls::ACCEPT, 43);
        assert_eq!(syscalls::BIND, 49);
        assert_eq!(syscalls::LISTEN, 50);
    }

    #[test]
    fn test_syscall_constants_process() {
        // Verify process management syscall constants
        assert_eq!(syscalls::FORK, 57);
        assert_eq!(syscalls::VFORK, 58);
        assert_eq!(syscalls::EXECVE, 59);
        assert_eq!(syscalls::EXIT, 60);
        assert_eq!(syscalls::WAIT4, 61);
        assert_eq!(syscalls::KILL, 62);
    }

    #[test]
    fn test_syscall_constants_epoll() {
        // Verify epoll syscall constants
        assert_eq!(syscalls::EPOLL_CREATE, 213);
        assert_eq!(syscalls::EPOLL_WAIT, 232);
        assert_eq!(syscalls::EPOLL_CTL, 233);
        assert_eq!(syscalls::EPOLL_CREATE1, 291);
    }
}
