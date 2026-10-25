set(firmware_dir "${CMAKE_CURRENT_LIST_DIR}/../../firmware/rp2350")
add_executable(rp2350_factory_provision EXCLUDE_FROM_ALL main.c provisioning.c
    "${firmware_dir}/presence.c" "${firmware_dir}/entropy.c" "${firmware_dir}/board_entropy.c")
target_include_directories(rp2350_factory_provision PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(rp2350_factory_provision PRIVATE rp2350_storage_codec
    rp2350_board_flash hardware_watchdog pico_bootrom pico_stdlib)
target_compile_options(rp2350_factory_provision PRIVATE -fstack-usage)
target_compile_definitions(rp2350_factory_provision PRIVATE PICO_STACK_SIZE=16384 PICO_CORE1_STACK_SIZE=0)
pico_enable_stdio_usb(rp2350_factory_provision 0)
pico_enable_stdio_uart(rp2350_factory_provision 0)
pico_add_linker_script_override_path(rp2350_factory_provision "${CMAKE_CURRENT_SOURCE_DIR}/linker"
    FILES section_extra_post_end.incl)
pico_add_linker_script_override_path(rp2350_factory_provision "${firmware_dir}/linker"
    FILES memory_ram.incl sections_stack.incl)
target_link_options(rp2350_factory_provision PRIVATE -Wl,--print-memory-usage)
pico_set_program_name(rp2350_factory_provision "TunnlixKey factory provisioning (RAM only)")
pico_set_binary_type(rp2350_factory_provision no_flash)
pico_add_extra_outputs(rp2350_factory_provision)
set_source_files_properties(main.c provisioning.c PROPERTIES
    COMPILE_OPTIONS "-std=c17;-Wall;-Wextra;-Wpedantic;-Werror")
