FetchContent_Declare(
  fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG        11.0.2
)
FetchContent_MakeAvailable(fmt)

list(APPEND PROJECT_LIBRARIES_LIST fmt::fmt)

