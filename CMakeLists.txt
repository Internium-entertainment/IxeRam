cmake_minimum_required(VERSION 3.14)
project(LowLevelMemoryDebugger VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Fetch FTXUI
include(FetchContent)
FetchContent_Declare(ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/ftxui
  GIT_TAG v5.0.0
)
FetchContent_MakeAvailable(ftxui)

include_directories(include)

# Find Capstone & Keystone
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)
pkg_check_modules(KEYSTONE REQUIRED keystone)

add_executable(memdebug
    src/main.cpp
    src/MemoryEngine.cpp
    src/Scanner.cpp
    src/TUI.cpp
    src/TUI_run.cpp
)

target_link_libraries(memdebug
    PRIVATE ftxui::screen ftxui::dom ftxui::component
    PRIVATE ${CAPSTONE_LIBRARIES} ${KEYSTONE_LIBRARIES}
    PRIVATE pthread
)
target_include_directories(memdebug PRIVATE ${CAPSTONE_INCLUDE_DIRS} ${KEYSTONE_INCLUDE_DIRS})

add_library(speedhack SHARED src/speedhack.c)
target_link_libraries(speedhack PRIVATE dl)
set_target_properties(speedhack PROPERTIES POSITION_INDEPENDENT_CODE ON)

