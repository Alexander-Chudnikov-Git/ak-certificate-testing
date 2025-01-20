FetchContent_Declare(
  libakrypt
  GIT_REPOSITORY https://git.miem.hse.ru/axelkenzo/libakrypt-0.x.git
  GIT_TAG        0.9.16
)

set(AK_TOOL OFF CACHE BOOL "Disable AK_TOOL")
set(CMAKE_C_FLAGS "-march=native" CACHE INTERNAL "Set march")

FetchContent_MakeAvailable(libakrypt)

list(APPEND PROJECT_INCLUDE_DIRS ${libakrypt_BINARY_DIR})
list(APPEND PROJECT_INCLUDE_DIRS ${libakrypt_SOURCE_DIR}/source)

list(APPEND PROJECT_LIBRARIES_LIST akrypt-shared)
