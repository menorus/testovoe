#include "shared_buffer.h"
#include "common.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <ctime>
#include <cstdio>
#include <sys/types.h>
#include <sys/syscall.h>

static SharedBuffer* buffer = nullptr;
constexpr const char* SHM_NAME = "/ld_preload_log_shm";

static pid_t get_tid() {
    return syscall(SYS_gettid);
}

void init_shared_buffer() {
    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    ftruncate(fd, sizeof(SharedBuffer));
    void* addr = mmap(nullptr, sizeof(SharedBuffer), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);

    buffer = static_cast<SharedBuffer*>(addr);

    // Только при первом запуске
    static bool initialized = false;
    if (!initialized) {
        buffer->write_index = 0;
        buffer->read_index = 0;
        initialized = true;
    }
}

static void write_log(LogType type, const char* message) {
    if (!buffer) return;

    size_t index = buffer->write_index.fetch_add(1) % 1024;
    LogEntry& entry = buffer->entries[index];

    entry.type = type;
    entry.timestamp = std::time(nullptr);
    entry.pid = getpid();
    entry.tid = get_tid();
    strncpy(entry.data, message, MAX_LOG_MESSAGE_SIZE - 1);
    entry.data[MAX_LOG_MESSAGE_SIZE - 1] = '\0';
}

void log_file_open(const char* filename, int flags, int fd) {
    char msg[MAX_LOG_MESSAGE_SIZE];
    snprintf(msg, sizeof(msg), "open(\"%s\", flags=0x%x) = %d", filename, flags, fd);
    write_log(LogType::OPEN, msg);
}

void log_file_close(int fd, int result) {
    char msg[MAX_LOG_MESSAGE_SIZE];
    snprintf(msg, sizeof(msg), "close(%d) = %d", fd, result);
    write_log(LogType::CLOSE, msg);
}

void log_lseek(int fd, off_t offset, int whence, off_t result) {
    char msg[MAX_LOG_MESSAGE_SIZE];
    snprintf(msg, sizeof(msg), "lseek(%d, %ld, %d) = %ld", fd, (long)offset, whence, (long)result);
    write_log(LogType::LSEEK, msg);
}

void log_read(int fd, const void* buf, size_t count, ssize_t bytes_read) {
    char msg[MAX_LOG_MESSAGE_SIZE];
    snprintf(msg, sizeof(msg), "read(%d, buf=%p, %zu) = %zd", fd, buf, count, bytes_read);
    write_log(LogType::READ, msg);
}

void log_write(int fd, const void* buf, size_t count, ssize_t bytes_written) {
    char msg[MAX_LOG_MESSAGE_SIZE];
    snprintf(msg, sizeof(msg), "write(%d, buf=%p, %zu) = %zd", fd, buf, count, bytes_written);
    write_log(LogType::WRITE, msg);
}

void log_malloc(size_t size, void* result_ptr) {
    char msg[MAX_LOG_MESSAGE_SIZE];
    snprintf(msg, sizeof(msg), "malloc(%zu) = %p", size, result_ptr);
    write_log(LogType::MALLOC, msg);
}

void log_free(void* ptr) {
    char msg[MAX_LOG_MESSAGE_SIZE];
    snprintf(msg, sizeof(msg), "free(%p)", ptr);
    write_log(LogType::FREE, msg);
}

void log_realloc(void* old_ptr, size_t new_size, void* new_ptr) {
    char msg[MAX_LOG_MESSAGE_SIZE];
    snprintf(msg, sizeof(msg), "realloc(%p, %zu) = %p", old_ptr, new_size, new_ptr);
    write_log(LogType::REALLOC, msg);
}

void cleanup_shared_buffer() {
    if (buffer) {
        munmap(buffer, sizeof(SharedBuffer));
        buffer = nullptr;
    }
}
