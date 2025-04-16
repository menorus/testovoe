#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "common.h"

constexpr const char* SHM_NAME = "/ld_preload_log_shm";

bool is_mem_log(LogType type) {
    return type == LogType::MALLOC || type == LogType::FREE ||
        type == LogType::REALLOC;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: mem_logger <poll_interval_ms> <log_file>\n";
        return 1;
    }

    int interval_ms = std::stoi(argv[1]);
    const char* log_filename = argv[2];

    int shm_fd = shm_open(SHM_NAME, O_RDWR, 0666);
    if (shm_fd < 0) {
        perror("shm_open");
        return 1;
    }

    void* addr = mmap(nullptr, sizeof(SharedBuffer), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    close(shm_fd);
    if (addr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    SharedBuffer* buffer = static_cast<SharedBuffer*>(addr);
    std::ofstream log_file(log_filename, std::ios::app);

    size_t read_index = 0;

    while (true) {
        while (read_index < buffer->write_index) {
            const LogEntry& entry = buffer->entries[read_index % 1024];
            if (is_mem_log(entry.type)) {
                log_file << "[" << entry.timestamp << "] "
                    << "PID " << entry.pid << " TID " << entry.tid << " "
                    << entry.data << "\n";
            }
            ++read_index;
        }
        log_file.flush();
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
    }

    munmap(buffer, sizeof(SharedBuffer));
    return 0;
}
