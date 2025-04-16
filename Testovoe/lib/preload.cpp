#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>
#include <cstring>
#include "shared_buffer.h"

static bool initialized = false;

__attribute__((constructor))
void preload_init() {
    if (!initialized) {
        init_shared_buffer();
        initialized = true;
    }
}

__attribute__((destructor))
void preload_cleanup() {
    if (initialized) {
        cleanup_shared_buffer();
    }
}


// File I/O Intercepts


extern "C" int open(const char* pathname, int flags, ...) {
    static int (*real_open)(const char*, int, mode_t) = nullptr;
    if (!real_open) real_open = (int (*)(const char*, int, mode_t)) dlsym(RTLD_NEXT, "open");

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    int fd = real_open(pathname, flags, mode);

    char info[256];
    snprintf(info, sizeof(info), "open('%s', flags=0x%x) => fd=%d", pathname, flags, fd);
    log_event(LogType::OPEN, info);

    return fd;
}

extern "C" int close(int fd) {
    static int (*real_close)(int) = nullptr;
    if (!real_close) real_close = (int (*)(int)) dlsym(RTLD_NEXT, "close");

    int result = real_close(fd);

    char info[128];
    snprintf(info, sizeof(info), "close(fd=%d) => %d", fd, result);
    log_event(LogType::CLOSE, info);

    return result;
}

extern "C" off_t lseek(int fd, off_t offset, int whence) {
    static off_t(*real_lseek)(int, off_t, int) = nullptr;
    if (!real_lseek) real_lseek = (off_t(*)(int, off_t, int)) dlsym(RTLD_NEXT, "lseek");

    off_t result = real_lseek(fd, offset, whence);

    char info[128];
    snprintf(info, sizeof(info), "lseek(fd=%d, offset=%ld, whence=%d) => %ld",
        fd, static_cast<long>(offset), whence, static_cast<long>(result));
    log_event(LogType::LSEEK, info);

    return result;
}

extern "C" ssize_t read(int fd, void* buf, size_t count) {
    static ssize_t(*real_read)(int, void*, size_t) = nullptr;
    if (!real_read) real_read = (ssize_t(*)(int, void*, size_t)) dlsym(RTLD_NEXT, "read");

    ssize_t bytes = real_read(fd, buf, count);

    char info[128];
    snprintf(info, sizeof(info), "read(fd=%d, count=%zu) => %zd", fd, count, bytes);
    log_event(LogType::READ, info);

    return bytes;
}

extern "C" ssize_t write(int fd, const void* buf, size_t count) {
    static ssize_t(*real_write)(int, const void*, size_t) = nullptr;
    if (!real_write) real_write = (ssize_t(*)(int, const void*, size_t)) dlsym(RTLD_NEXT, "write");

    ssize_t bytes = real_write(fd, buf, count);

    char info[128];
    snprintf(info, sizeof(info), "write(fd=%d, count=%zu) => %zd", fd, count, bytes);
    log_event(LogType::WRITE, info);

    return bytes;
}


// Memory Management Intercepts


extern "C" void* malloc(size_t size) {
    static void* (*real_malloc)(size_t) = nullptr;
    if (!real_malloc) real_malloc = (void* (*)(size_t)) dlsym(RTLD_NEXT, "malloc");

    void* ptr = real_malloc(size);

    char info[128];
    snprintf(info, sizeof(info), "malloc(%zu) => %p", size, ptr);
    log_event(LogType::MALLOC, info);

    return ptr;
}

extern "C" void free(void* ptr) {
    static void (*real_free)(void*) = nullptr;
    if (!real_free) real_free = (void (*)(void*)) dlsym(RTLD_NEXT, "free");

    char info[128];
    snprintf(info, sizeof(info), "free(%p)", ptr);
    log_event(LogType::FREE, info);

    real_free(ptr);
}

extern "C" void* realloc(void* ptr, size_t size) {
    static void* (*real_realloc)(void*, size_t) = nullptr;
    if (!real_realloc) real_realloc = (void* (*)(void*, size_t)) dlsym(RTLD_NEXT, "realloc");

    void* new_ptr = real_realloc(ptr, size);

    char info[128];
    snprintf(info, sizeof(info), "realloc(%p, %zu) => %p", ptr, size, new_ptr);
    log_event(LogType::REALLOC, info);

    return new_ptr;
}
