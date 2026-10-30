#pragma once

// Framework-free assertions; swap to Catch2 once the suite grows.

#include <cstdlib>
#include <iostream>

inline int g_failures = 0;

#define CHECK(expr)                                                              \
    do {                                                                         \
        if (!(expr)) {                                                           \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #expr \
                      << "\n";                                                   \
            ++g_failures;                                                        \
        }                                                                        \
    } while (0)

inline int finish(const char* suite) {
    if (g_failures == 0) std::cout << suite << ": all tests passed\n";
    else std::cerr << suite << ": " << g_failures << " check(s) failed\n";
    return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
