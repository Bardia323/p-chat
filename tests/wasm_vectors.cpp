// The vectors made again in WebAssembly: under Node and in a browser, the
// same function as the native tool, compared byte for byte with the file.
#include "vectors.hpp"
#include <emscripten/bind.h>

namespace {
std::string vectors_json() { return vectors::to_json(vectors::compute()); }
}  // namespace

EMSCRIPTEN_BINDINGS(sgchat_vectors) { emscripten::function("vectors", &vectors_json); }
