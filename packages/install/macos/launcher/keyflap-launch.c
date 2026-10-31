/* keyflap-launch: hands a launchd job's Sockets to a program the way systemd socket activation does. */

typedef unsigned long size_t;
typedef long ssize_t;

int launch_activate_socket(const char *name, int **fds, size_t *cnt);
int *__error(void);
char *strerror(int err);
ssize_t write(int fd, const void *buf, size_t n);
int fcntl(int fd, int cmd, ...);
int dup2(int from, int to);
int close(int fd);
int getpid(void);
unsigned getuid(void);
unsigned geteuid(void);
unsigned getgid(void);
unsigned getegid(void);
int setenv(const char *name, const char *value, int overwrite);
int execv(const char *path, char *const argv[]);

enum { ESRCH = 3, FIRST_FD = 3, MAX_FDS = 64, MAX_NAME = 128, F_DUPFD = 0, F_SETFD = 2 };

static int same(const char *a, const char *b) {
  while (*a && *a == *b) a++, b++;
  return *a == *b;
}

static void put(const char *s) {
  size_t n = 0;
  while (s[n]) n++;
  write(2, s, n);
}

static int fail(const char *what, const char *name, const char *why) {
  put("keyflap-launch: ");
  put(what);
  put(name);
  if (*why) put(": "), put(why);
  put("\n");
  return 1;
}

static int valid_name(const char *s) {
  int n = 0;
  for (; s[n]; n++) {
    char ch = s[n];
    int ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
             ch == '_' || (n > 0 && (ch == '.' || ch == '-'));
    if (!ok || n == MAX_NAME) return 0;
  }
  return n > 0;
}

static char *decimal(int v, char *end) {
  *--end = 0;
  do *--end = (char)('0' + v % 10); while (v /= 10);
  return end;
}

int main(int argc, char **argv) {
  const char *names[MAX_FDS];
  int held[MAX_FDS];
  char joined[MAX_FDS * (MAX_NAME + 1)], pid[16], count[16];
  int n = 0, i = 1, at = 0;

  if (getuid() == 0 || geteuid() == 0 || getgid() == 0 || getegid() == 0)
    return fail("refusing to run as root", "", "");
  for (; i < argc && !same(argv[i], "--"); i += 2) {
    if (!same(argv[i], "--socket") || i + 1 >= argc)
      return fail("usage: keyflap-launch --socket NAME [--socket NAME]... -- /abs/program [args]", "", "");
    if (!valid_name(argv[i + 1])) return fail("bad socket name", "", "");
    if (n == MAX_FDS) return fail("too many sockets", "", "");
    for (int j = 0; j < n; j++)
      if (same(names[j], argv[i + 1])) return fail("socket named twice: ", argv[i + 1], "");
    names[n++] = argv[i + 1];
  }
  if (n == 0) return fail("no --socket given", "", "");
  if (i + 1 >= argc || argv[i + 1][0] != '/') return fail("program path must be absolute", "", "");

  for (int k = 0; k < n; k++) {
    int *fds = 0;
    size_t cnt = 0;
    int err = launch_activate_socket(names[k], &fds, &cnt);
    if (err == ESRCH) return fail("launchd socket ", names[k], "not in this launchd job");
    if (err != 0) return fail("launchd socket ", names[k], strerror(err));
    if (cnt != 1) return fail("launchd socket ", names[k], "want exactly one fd");
    if (fds[0] < FIRST_FD) return fail("launchd socket ", names[k], "fd below 3");
    held[k] = fcntl(fds[0], F_DUPFD, FIRST_FD + MAX_FDS);
    if (held[k] < 0) return fail("dup ", names[k], strerror(*__error()));
    close(fds[0]);
  }
  for (int k = 0; k < n; k++) {
    if (dup2(held[k], FIRST_FD + k) != FIRST_FD + k || fcntl(FIRST_FD + k, F_SETFD, 0) != 0)
      return fail("dup2 ", names[k], strerror(*__error()));
    close(held[k]);
    for (const char *s = names[k]; *s; s++) joined[at++] = *s;
    joined[at++] = k + 1 < n ? ':' : 0;
  }

  if (setenv("LISTEN_PID", decimal(getpid(), pid + sizeof pid), 1) != 0 ||
      setenv("LISTEN_FDS", decimal(n, count + sizeof count), 1) != 0 ||
      setenv("LISTEN_FDNAMES", joined, 1) != 0)
    return fail("setenv failed", "", "");
  execv(argv[i + 1], argv + i + 1);
  return fail("exec ", argv[i + 1], strerror(*__error()));
}
