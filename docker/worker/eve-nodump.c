/*
 * eve-nodump.so: preloaded into a runner pod's own processes (tini, the
 * entrypoint and the runner's node) through LD_PRELOAD. As each process
 * starts, it marks the process non-dumpable, so job code running as the same
 * UID cannot read its /proc/<pid>/environ or memory.
 *
 * The long-lived services get the same property from execute-only copies of
 * node and tini: the kernel marks a process non-dumpable when it executes a
 * binary its user cannot read. gVisor, which sandboxes runner pods, cannot
 * load an execute-only binary, so runner pods start the ordinary binaries
 * with this library instead.
 *
 * execve() makes a process dumpable again, so the library acts in each
 * process it is loaded into. Job processes never load it: their environments
 * are allowlists that leave LD_PRELOAD out.
 *
 * If the kernel refuses, the process exits rather than run exposed.
 */
#include <sys/prctl.h>
#include <unistd.h>

__attribute__((constructor)) static void eve_nodump(void) {
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 || prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) {
    static const char message[] = "eve-nodump: cannot mark this process non-dumpable; exiting\n";
    (void)!write(STDERR_FILENO, message, sizeof message - 1);
    _exit(126);
  }
}
