#pragma once

#include <cstddef>


void init_shared_buffer();

// Перехваченные функции для логирования
void log_file_open(const char* filename, int flags, int fd);
void log_file_close(int fd, int result);
void log_lseek(int fd, off_t offset, int whence, off_t result);
void log_read(int fd, const void* buf, size_t count, ssize_t bytes_read);
void log_write(int fd, const void* buf, size_t count, ssize_t bytes_written);

void log_malloc(size_t size, void* result_ptr);
void log_free(void* ptr);
void log_realloc(void* old_ptr, size_t new_size, void* new_ptr);

// Очистка или отцепление от shared memory (если нужно)
void cleanup_shared_buffer();
