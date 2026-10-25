# Warnings, hardening and sanitizer flags shared by every KryptonFS target.
# Call kfs_apply_defaults(<target>) after defining a target.

function(kfs_apply_defaults target)
    target_compile_options(${target} PRIVATE
        -Wall -Wextra -Wpedantic
        -Wshadow -Wconversion -Wsign-conversion
        -Wformat=2 -Wstrict-prototypes -Wmissing-prototypes
        -Wcast-qual -Wvla -Wnull-dereference)
    if(KFS_WARNINGS_AS_ERRORS)
        target_compile_options(${target} PRIVATE -Werror)
    endif()

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # These daemons start as root and handle key material: stack
        # canaries, fortified libc calls (needs optimization, so not in
        # Debug), and full RELRO so the GOT is read-only after startup.
        # -U first because distro compilers often predefine the macro.
        target_compile_options(${target} PRIVATE
            -fstack-protector-strong -fstack-clash-protection
            "$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE;-D_FORTIFY_SOURCE=3>")
        target_link_options(${target} PRIVATE
            -Wl,-z,relro,-z,now -Wl,-z,noexecstack)
    elseif(MINGW)
        # C99-conforming printf family, so %zu and %llu behave.
        target_compile_definitions(${target} PRIVATE __USE_MINGW_ANSI_STDIO=1)
    endif()

    if(KFS_SANITIZE)
        target_compile_options(${target} PRIVATE
            -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
endfunction()
