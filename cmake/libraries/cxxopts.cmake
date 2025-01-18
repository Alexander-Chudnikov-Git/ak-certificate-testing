FetchContent_Declare(
  cxxopts
  GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
  GIT_TAG        v3.2.0
)

FetchContent_GetProperties(cxxopts)

if(NOT cxxopts_POPULATED)
  FetchContent_MakeAvailable(cxxopts)
endif()

list(APPEND PROJECT_LIBRARIES_LIST cxxopts::cxxopts)

