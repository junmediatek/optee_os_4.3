#include "logger.h"
#include <stdio.h>
#include <time.h>
#include <string.h> // For strncpy, strlen, memset, strcat
#include <stdarg.h> // For va_list, va_start, va_end, vsnprintf

static FILE* log_file = NULL;
static LogLevel current_log_level = LOG_LEVEL_DEBUG; // Default log level

// Helper to get current time as string
static void get_timestamp(char* buffer, size_t len) {
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    if (t) {
        strftime(buffer, len, "%Y-%m-%d %H:%M:%S", t);
    } else {
        // Fallback if localtime fails
        strncpy(buffer, "                   ", len); // 19 spaces
        if (len > 0) buffer[len-1] = '\0';
    }
}

// Helper to convert log level to string
static const char* level_to_string_internal(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO:  return "INFO "; // Padded for alignment
        case LOG_LEVEL_WARNING: return "WARN "; // Padded
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_CRASH: return "CRASH";
        default: return "UNKWN"; // Padded
    }
}

void Logger_Init(const char* log_file_path) {
    if (log_file_path) {
        log_file = fopen(log_file_path, "a"); // Append mode
        if (!log_file) {
            perror("Logger_Init: Failed to open log file");
            // Continue with stderr logging if file opening fails
        }
    }
    char timestamp[30];
    get_timestamp(timestamp, sizeof(timestamp));
    const char* effective_log_path = log_file_path ? log_file_path : "stderr";

    const char* msg_format = "[%s] [%s] Logger initialized. Logging to %s.\n";
    if (log_file) {
        fprintf(log_file, msg_format, timestamp, level_to_string_internal(LOG_LEVEL_INFO), effective_log_path);
        fflush(log_file);
    } else {
        fprintf(stderr, msg_format, timestamp, level_to_string_internal(LOG_LEVEL_INFO), effective_log_path);
        fflush(stderr);
    }
}

void Logger_SetLevel(LogLevel level) {
    current_log_level = level;
    char timestamp[30];
    get_timestamp(timestamp, sizeof(timestamp));
    const char* msg_format = "[%s] [%s] Log level set to %s\n";
    if (log_file) {
        fprintf(log_file, msg_format, timestamp, level_to_string_internal(LOG_LEVEL_INFO), level_to_string_internal(level));
        fflush(log_file);
    } else {
        fprintf(stderr, msg_format, timestamp, level_to_string_internal(LOG_LEVEL_INFO), level_to_string_internal(level));
        fflush(stderr);
    }
}

void Logger_Log(LogLevel level, const char* format, ...) {
    if (level < current_log_level) {
        return;
    }

    char timestamp[30];
    get_timestamp(timestamp, sizeof(timestamp));

    char log_buffer[2048]; // Increased buffer for log messages
    va_list args;
    va_start(args, format);
    vsnprintf(log_buffer, sizeof(log_buffer), format, args);
    va_end(args);

    const char* msg_format = "[%s] [%s] %s\n";
    if (log_file) {
        fprintf(log_file, msg_format, timestamp, level_to_string_internal(level), log_buffer);
        fflush(log_file);
    } else {
        fprintf(stderr, msg_format, timestamp, level_to_string_internal(level), log_buffer);
        fflush(stderr);
    }
}

void Logger_LogData(LogLevel level, const char* prefix, const uint8_t* data, size_t len) {
    if (level < current_log_level) {
        return;
    }
    if (!data || len == 0) {
        Logger_Log(level, "%s: (null or empty data)", prefix ? prefix : "Data");
        return;
    }

    Logger_Log(level, "%s (length: %zu bytes):", prefix ? prefix : "Data dump", len);

    const size_t bytes_per_line = 16;
    char hex_buffer[bytes_per_line * 3 + 1]; // for "XX XX ... XX "
    char char_buffer[bytes_per_line + 1];    // for "char_representation"

    for (size_t i = 0; i < len; i += bytes_per_line) {
        memset(hex_buffer, 0, sizeof(hex_buffer));
        memset(char_buffer, 0, sizeof(char_buffer));
        size_t line_len = (len - i < bytes_per_line) ? (len - i) : bytes_per_line;
        
        size_t hex_idx = 0;
        for (size_t j = 0; j < line_len; ++j) {
            sprintf(hex_buffer + hex_idx, "%02X ", data[i + j]);
            hex_idx += 3;
            char_buffer[j] = (data[i + j] >= 32 && data[i + j] <= 126) ? (char)data[i + j] : '.';
        }
        // Pad hex_buffer if line_len < bytes_per_line
        for (size_t j = line_len; j < bytes_per_line; ++j) {
            strcat(hex_buffer, "   "); // 3 spaces for padding
        }

        Logger_Log(level, "  %08zX: %s %s", i, hex_buffer, char_buffer);
    }
}

void Logger_Shutdown(void) {
    char timestamp[30];
    get_timestamp(timestamp, sizeof(timestamp));
    const char* msg = "[%s] [%s] Logger shutting down.\n";
    if (log_file) {
        fprintf(log_file, msg, timestamp, level_to_string_internal(LOG_LEVEL_INFO));
        fclose(log_file);
        log_file = NULL;
    } else {
        // If logging to stderr, no specific shutdown needed for the stream itself
        fprintf(stderr, msg, timestamp, level_to_string_internal(LOG_LEVEL_INFO));
        fflush(stderr);
    }
}

