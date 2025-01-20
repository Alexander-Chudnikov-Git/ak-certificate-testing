FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG        v1.15.0
)

set(SPDLOG_BUILD_SHARED ON CACHE BOOL "Build spdlog as a shared library" FORCE)

FetchContent_MakeAvailable(spdlog)

list(APPEND PROJECT_LIBRARIES_LIST spdlog::spdlog)

target_compile_definitions(${PROJECT_NAME} PRIVATE SPDLOG_ENABLE_SYSLOG)

