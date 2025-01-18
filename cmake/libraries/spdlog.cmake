FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG        v1.15.0
)

FetchContent_GetProperties(spdlog)

if(NOT spdlog_POPULATED)
  set(SPDLOG_BUILD_SHARED OFF CACHE BOOL "Build spdlog as a static library" FORCE)

  FetchContent_MakeAvailable(spdlog)
endif()

list(APPEND PROJECT_LIBRARIES_LIST spdlog::spdlog)

target_compile_definitions(${PROJECT_NAME} PRIVATE SPDLOG_ENABLE_SYSLOG)

