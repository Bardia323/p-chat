// A check that says what failed and where, and a count for the end.
#pragma once
#include <cstdio>
#include <cstdlib>
#include <string>

namespace sgchat_test {
inline int& failures() { static int n = 0; return n; }
inline void check(bool ok, const std::string& what, const char* file, int line) {
    if (ok) return;
    std::fprintf(stderr, "FAIL %s:%d %s\n", file, line, what.c_str());
    ++failures();
}
inline int finish(const char* name) {
    if (failures()) { std::fprintf(stderr, "%s: %d failed\n", name, failures()); return 1; }
    std::printf("%s: ok\n", name);
    return 0;
}
}  // namespace sgchat_test

#define CHECK(cond) ::sgchat_test::check((cond), #cond, __FILE__, __LINE__)
#define CHECK_MSG(cond, msg) ::sgchat_test::check((cond), (msg), __FILE__, __LINE__)
#define CHECK_THROWS(expr)                                                     \
    do {                                                                       \
        bool threw_ = false;                                                   \
        try { expr; } catch (const std::exception&) { threw_ = true; }         \
        ::sgchat_test::check(threw_, "expected a refusal: " #expr, __FILE__, __LINE__); \
    } while (0)
