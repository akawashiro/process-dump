#include <sys/ptrace.h>

#include <cstring>
#include <iostream>

int main(int argc, char* argv[]) {
    pid_t pid = atoi(argv[1]);
    char buf[1024];
    std::string proc = std::string("/proc/") + argv[1] + "/maps";
    FILE* fp = fopen(proc.c_str(), "r");

    while (fgets(buf, 1024, fp) != NULL) {
        uint64_t start, end;
        sscanf(buf, "%lx-%lx", &start, &end);
        if (strstr(buf, "libc-2.31.so") == NULL) continue;
        printf("%s", buf);

        for (uint64_t addr = start; addr < end; addr += sizeof(long)) {
            if (addr % (sizeof(long) * 16) == 0) {
                printf("%lx ", addr);
            }
            long ret = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
            if (ret == -1 && errno != 0) {
                printf("\n%s\n", strerror(errno));
                return 1;
            }
            printf("%lx ", ret);
            if (addr % (sizeof(long) * 16) == (sizeof(long) * 15)) {
                printf("\n");
            }
        }
        printf("\n");
    }
}
