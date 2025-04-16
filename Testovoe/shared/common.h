#pragma once

#include <ctime>
#include <cstdint>
#include <atomic>

enum class LogType : uint8_t {
    OPEN,
    CLOSE,
    LSEEK,
    READ,
    WRITE,
    MALLOC,
    FREE,
    REALLOC
};

// Максимальный размер одного сообщения в байтах
constexpr size_t MAX_LOG_MESSAGE_SIZE = 256;

// Запись лога
struct LogEntry {
    LogType type;
    std::time_t timestamp;
    pid_t pid;
    pid_t tid;
    char data[MAX_LOG_MESSAGE_SIZE];  
};

// Кольцевой буфер в shared memory
struct SharedBuffer {
    std::atomic<size_t> write_index;
    std::atomic<size_t> read_index;
    LogEntry entries[1024];  
};
