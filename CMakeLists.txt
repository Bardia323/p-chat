# sgchat - a messenger whose conversations are stategine states.
#
# The engine is fetched like any project's (a pinned commit); to build
# against the checkout beside this folder, configure with
#   -DFETCHCONTENT_SOURCE_DIR_STATEGINE=../stategine
# The same file builds natively (laws, vectors, relay checks) and under
# Emscripten (the browser app), as the engine's own browser build does.
cmake_minimum_required(VERSION 3.21)
project(sgchat LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# A messenger needs no network GPU backend and no native ICE: the browser
# brings its own WebRTC, and the numerics are only the placeholder epoch.
set(SG_NET_CUDA OFF CACHE BOOL "" FORCE)
set(SG_NET_ICE OFF CACHE BOOL "" FORCE)

# In the browser a refusal is an exception like anywhere else: caught, not
# an abort of the whole module (the engine sets the same for its own targets).
if(EMSCRIPTEN)
  add_compile_options(-fexceptions)
  add_link_options(-fexceptions)
endif()

include(FetchContent)
FetchContent_Declare(stategine
  GIT_REPOSITORY https://github.com/Bardia323/stategine.git
  GIT_TAG        c0e4919d359babb29eb93b79b2f5e8004632abcd
  EXCLUDE_FROM_ALL)  # build only what sgchat's targets need
FetchContent_MakeAvailable(stategine)
include(${stategine_SOURCE_DIR}/cmake/StategineModules.cmake)

enable_testing()

# The protocol, its crypto, its trust and the inside of the world's arrows.
# Headers in include/chat, bodies in src/chat; both held to the engine's shape.
stategine_module(chat DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/chat
                 ROOT ${CMAKE_CURRENT_SOURCE_DIR}/include INCLUDED_AS chat)
target_link_libraries(chat PUBLIC stategine::net stategine::dsl sg_net_crypto)
set_property(GLOBAL APPEND PROPERTY STATEGINE_MODULES "chat=${CMAKE_CURRENT_SOURCE_DIR}/include/chat:")

# The word list and the emoji list are data files, compiled in as they are.
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/data/words.txt SGCHAT_WORDS)
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/data/emoji.txt SGCHAT_EMOJI)
# So are the conversation and device templates the edits compile.
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/world/conversation.sg SGCHAT_CONVERSATION)
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/world/device.sg SGCHAT_DEVICE)
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/world/call.sg SGCHAT_CALL)
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/world/game.sg SGCHAT_GAME)
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/world/board.sg SGCHAT_BOARD)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  ${CMAKE_CURRENT_SOURCE_DIR}/data/words.txt ${CMAKE_CURRENT_SOURCE_DIR}/data/emoji.txt
  ${CMAKE_CURRENT_SOURCE_DIR}/world/conversation.sg ${CMAKE_CURRENT_SOURCE_DIR}/world/device.sg
  ${CMAKE_CURRENT_SOURCE_DIR}/world/call.sg ${CMAKE_CURRENT_SOURCE_DIR}/world/game.sg
  ${CMAKE_CURRENT_SOURCE_DIR}/world/board.sg)
configure_file(src/chat/Lists.cpp.in ${CMAKE_CURRENT_BINARY_DIR}/generated/Lists.cpp @ONLY)
target_sources(chat PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated/Lists.cpp)
stategine_compile_dsl(chat NAME chat SOURCES world/chat.sg)

# Each native check is one program and one test, given the vectors folder.
set(SGCHAT_TESTS link vectors world trust ratchet app media call live)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/phases.cmake OPTIONAL)

# Native devices (v1 §9): a WebSocket client, the relay's frames and a host
# that keeps its own keys - what a bot is made of - and the echo bot.
if(NOT EMSCRIPTEN)
  find_package(OpenSSL REQUIRED)
  add_library(sgchat_host STATIC bot/Socket.cpp bot/Relay.cpp bot/Host.cpp)
  target_include_directories(sgchat_host PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/bot)
  target_link_libraries(sgchat_host PUBLIC chat OpenSSL::SSL OpenSSL::Crypto)
  add_executable(sgchat_echo bot/echo.cpp)
  target_link_libraries(sgchat_echo PRIVATE sgchat_host)
endif()

if(NOT EMSCRIPTEN)
  foreach(t ${SGCHAT_TESTS})
    add_executable(sgchat_${t} tests/test_${t}.cpp)
    target_link_libraries(sgchat_${t} PRIVATE chat)
    target_include_directories(sgchat_${t} PRIVATE tests)
    add_test(NAME sgchat_${t} COMMAND sgchat_${t} ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors)
  endforeach()
  # The vectors are made by a program of their own, never by a test.
  add_executable(sgchat_make_vectors tools/make_vectors.cpp)
  target_link_libraries(sgchat_make_vectors PRIVATE chat)
  target_include_directories(sgchat_make_vectors PRIVATE tests)
  stategine_check_modules(NAME sgchat_modules)
  # The Python on PATH, the one with websockets (SGCHAT_PYTHON to choose another).
  find_program(SGCHAT_PYTHON NAMES python3 python)
  if(SGCHAT_PYTHON)
    add_test(NAME sgchat_relay COMMAND ${SGCHAT_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_relay.py)
    set_tests_properties(sgchat_relay PROPERTIES TIMEOUT 180)
    # The same checks against the Cloudflare Worker relay, under `wrangler dev` (when wrangler is here).
    find_program(SGCHAT_WRANGLER NAMES wrangler PATHS $ENV{HOME}/.local/bin)
    if(SGCHAT_WRANGLER)
      add_test(NAME sgchat_relay_worker COMMAND ${SGCHAT_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_relay.py
               --worker ${CMAKE_CURRENT_SOURCE_DIR}/relay/worker)
      set_tests_properties(sgchat_relay_worker PROPERTIES TIMEOUT 600 RUN_SERIAL TRUE)
    endif()
    add_executable(sgchat_bot tests/test_bot.cpp)
    target_link_libraries(sgchat_bot PRIVATE sgchat_host)
    target_include_directories(sgchat_bot PRIVATE tests)
    add_test(NAME sgchat_bot COMMAND sgchat_bot ${SGCHAT_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/relay/relay.py $<TARGET_FILE:sgchat_echo>)
    set_tests_properties(sgchat_bot PROPERTIES TIMEOUT 300)
  endif()
else()
  # The browser app: the world, the protocol and the engine's WebRTC
  # transport in one module; WebCrypto, IndexedDB and the DOM stay in JS.
  set(SGCHAT_WASM_FLAGS -sMODULARIZE=1 -sNO_EXIT_RUNTIME=1 -sALLOW_MEMORY_GROWTH=1 -sINITIAL_MEMORY=64MB
      -sSTACK_SIZE=1048576 -sENVIRONMENT=web,worker,node)
  add_executable(sgchat_web src/web/Bindings.cpp)
  target_link_libraries(sgchat_web PRIVATE chat stategine::web)
  target_link_options(sgchat_web PRIVATE ${SGCHAT_WASM_FLAGS} -sEXPORT_NAME=createChat --bind -sDYNAMIC_EXECUTION=0)
  set_target_properties(sgchat_web PROPERTIES OUTPUT_NAME sgchat)
  # The vectors, made again in Wasm: under Node here, and in a browser.
  add_executable(sgchat_vectors_wasm tests/wasm_vectors.cpp)
  target_link_libraries(sgchat_vectors_wasm PRIVATE chat)
  target_include_directories(sgchat_vectors_wasm PRIVATE tests)
  target_link_options(sgchat_vectors_wasm PRIVATE ${SGCHAT_WASM_FLAGS} -sEXPORT_NAME=createVectors --bind)
  # The release chain (web/release.js), and tools/release.py's chains checked by it.
  find_program(SGCHAT_PYTHON NAMES python3 python)
  add_test(NAME sgchat_release COMMAND node ${CMAKE_CURRENT_SOURCE_DIR}/tests/release_checks.mjs ${CMAKE_CURRENT_SOURCE_DIR}/web/release.js
           ${SGCHAT_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/tools/release.py ${CMAKE_CURRENT_BINARY_DIR})
  # Protocol 10: the in-person codes (web/direct.js) and contacts carrying (web/carry.js).
  add_test(NAME sgchat_direct COMMAND node ${CMAKE_CURRENT_SOURCE_DIR}/tests/direct_checks.mjs ${CMAKE_CURRENT_SOURCE_DIR}/web)
  add_test(NAME sgchat_vectors_node COMMAND node ${CMAKE_CURRENT_SOURCE_DIR}/tests/node_vectors.mjs
           ${CMAKE_CURRENT_BINARY_DIR}/sgchat_vectors_wasm.js ${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/v4.json)
  # In a real browser: a Chromium (SGCHAT_BROWSER) and the Python with
  # playwright, websockets and cryptography (SGCHAT_PYTHON).
  set(SGCHAT_BROWSER "" CACHE FILEPATH "Chrome or Chromium for the browser tests (a full one: the headless shell grants no notifications)")
  find_program(SGCHAT_PYTHON NAMES python3 python)
  if(SGCHAT_BROWSER AND SGCHAT_PYTHON)
    add_test(NAME sgchat_browser_vectors COMMAND ${SGCHAT_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_browser.py vectors
             --wasm ${CMAKE_CURRENT_BINARY_DIR} --browser ${SGCHAT_BROWSER})
    # The echo bot is native: built in the native build beside this one.
    set(SGCHAT_ECHO "${CMAKE_CURRENT_SOURCE_DIR}/build/sgchat_echo" CACHE FILEPATH "the native echo bot, for the browser test")
    add_test(NAME sgchat_e2e COMMAND ${SGCHAT_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_browser.py e2e
             --wasm ${CMAKE_CURRENT_BINARY_DIR} --browser ${SGCHAT_BROWSER} --echo ${SGCHAT_ECHO})
    set_tests_properties(sgchat_browser_vectors PROPERTIES TIMEOUT 300)
    set_tests_properties(sgchat_e2e PROPERTIES TIMEOUT 1200 RUN_SERIAL TRUE)
    add_test(NAME sgchat_release_browser COMMAND ${SGCHAT_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_browser.py release
             --wasm ${CMAKE_CURRENT_BINARY_DIR} --browser ${SGCHAT_BROWSER})
    set_tests_properties(sgchat_release_browser PROPERTIES TIMEOUT 900 RUN_SERIAL TRUE)
    # In real browsers: pairing in person, contacts carrying, devices relaying, no relay.
    add_test(NAME sgchat_meet COMMAND ${SGCHAT_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_browser.py meet
             --wasm ${CMAKE_CURRENT_BINARY_DIR} --browser ${SGCHAT_BROWSER})
    set_tests_properties(sgchat_meet PROPERTIES TIMEOUT 900 RUN_SERIAL TRUE)
    # Protocol 11: how fast a message gets between devices, live and by relay.
    add_test(NAME sgchat_lag COMMAND ${SGCHAT_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_browser.py lag
             --wasm ${CMAKE_CURRENT_BINARY_DIR} --browser ${SGCHAT_BROWSER})
    set_tests_properties(sgchat_lag PROPERTIES TIMEOUT 900 RUN_SERIAL TRUE)
    # The wide layout on a desktop window.
    add_test(NAME sgchat_desktop COMMAND ${SGCHAT_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_browser.py desktop
             --wasm ${CMAKE_CURRENT_BINARY_DIR} --browser ${SGCHAT_BROWSER})
    set_tests_properties(sgchat_desktop PROPERTIES TIMEOUT 900 RUN_SERIAL TRUE)
    # Protocol 11: linked devices, linking, syncing, the three unlinks.
    add_test(NAME sgchat_link_browser COMMAND ${SGCHAT_PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_browser.py link
             --wasm ${CMAKE_CURRENT_BINARY_DIR} --browser ${SGCHAT_BROWSER})
    set_tests_properties(sgchat_link_browser PROPERTIES TIMEOUT 900 RUN_SERIAL TRUE)
  endif()
endif()
