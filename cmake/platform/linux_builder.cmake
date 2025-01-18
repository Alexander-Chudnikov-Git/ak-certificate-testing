include(cmake/utils/get_linux_kernel.cmake)

if(CMAKE_RELEASE)
    add_compile_options(
        -fvisibility=hidden
        -pedantic
        -Wall
        -Wextra
        -Wcast-align
        -Wcast-qual
        -Wctor-dtor-privacy
        -Wformat=2
        -Winit-self
        -Wlogical-op
        -Wmissing-declarations
        -Wmissing-include-dirs
        -Wnoexcept
        -Woverloaded-virtual
        -Wredundant-decls
        -Wshadow
        -Wsign-promo
        -Wstrict-null-sentinel
        -Wswitch-default
        -Wundef
        -Wno-unused-variable
        -Wno-error=redundant-decls
        -Wno-uninitialized
        -Wno-strict-overflow
        -Ofast
    )
else()
    add_compile_options(
        -Wall
        -Wextra
    )
endif()

add_executable(${PROJECT_NAME} ${PROJECT_MAIN_SRC_FILES})

set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")

# install(TARGETS ${PROJECT_NAME} DESTINATION /usr/bin/) #
