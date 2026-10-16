// Writes the protocol's test vectors (tests/vectors.hpp) to a file. Run it
// when the protocol changes on purpose, read the difference, commit both.
#include "vectors.hpp"
#include <cstdio>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: sgchat_make_vectors <out.json>\n");
        return 2;
    }
    std::ofstream(argv[1]) << vectors::to_json(vectors::compute());
    std::printf("wrote %s\n", argv[1]);
    return 0;
}
