#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRASH
} LogLevel;

void Logger_Init(const char* log_file_path);
void Logger_Log(LogLevel level, const char* format, ...);
void Logger_LogData(LogLevel level, const char* prefix, const uint8_t* data, size_t len);
void Logger_SetLevel(LogLevel level);
void Logger_Shutdown(void);

#endif // LOGGER_H

