/* Just enough Linux for the testsim station on macOS. */
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#define SOCK_NONBLOCK 0
#include <netinet/tcp.h>
#define TCP_KEEPIDLE TCP_KEEPALIVE
#define st_ctim st_ctimespec
#define st_mtim st_mtimespec
#define st_atim st_atimespec
static inline int pipe2(int fds[2], int flags) {
    if (pipe(fds)) return -1;
    fcntl(fds[0], F_SETFL, flags); fcntl(fds[1], F_SETFL, flags);
    return 0;
}
#include <signal.h>
#define syncfs(fd) fsync(fd)
