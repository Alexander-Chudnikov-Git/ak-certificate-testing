FetchContent_Declare(
  libakrypt
  GIT_REPOSITORY https://git.miem.hse.ru/axelkenzo/libakrypt-0.x.git
  GIT_TAG        0.9.16
)

FetchContent_GetProperties(libakrypt)

if(NOT libakrypt_POPULATED)
  set(AK_TOOL OFF CACHE BOOL "Disable AK_TOOL")

  FetchContent_MakeAvailable(libakrypt)
endif()

list(APPEND PROJECT_LIBRARIES_LIST libakrypt-base.so libakrypt.so)
