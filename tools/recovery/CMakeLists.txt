function(key_configure_ram_recovery image title)
    target_include_directories(${image} PRIVATE "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../../include")
    target_link_libraries(${image} PRIVATE pico_stdlib pico_bootrom hardware_watchdog rp2350_status_led)
    target_compile_options(${image} PRIVATE -fstack-usage)
    target_compile_definitions(${image} PRIVATE PICO_STACK_SIZE=16384 PICO_CORE1_STACK_SIZE=0)
    pico_enable_stdio_usb(${image} 0)
    pico_enable_stdio_uart(${image} 0)
    pico_add_linker_script_override_path(${image} "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/linker"
        FILES section_extra_post_end.incl)
    pico_add_linker_script_override_path(${image} "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../../firmware/rp2350/linker"
        FILES memory_ram.incl sections_stack.incl)
    target_link_options(${image} PRIVATE -Wl,--print-memory-usage)
    pico_set_program_name(${image} "${title}")
    pico_set_binary_type(${image} no_flash)
    pico_add_extra_outputs(${image})
endfunction()

add_executable(rp2350_recovery EXCLUDE_FROM_ALL main.c)
key_configure_ram_recovery(rp2350_recovery "Key recovery probe (RAM only)")

add_executable(rp2350_layout_recovery EXCLUDE_FROM_ALL layout_reset.c
    ../../firmware/rp2350/update_gesture.c)
target_include_directories(rp2350_layout_recovery PRIVATE ../../firmware/rp2350)
target_link_libraries(rp2350_layout_recovery PRIVATE ctap_core hardware_flash)
key_configure_ram_recovery(rp2350_layout_recovery "Key boot-layout reset (RAM only)")
set_source_files_properties(main.c layout_reset.c PROPERTIES
    COMPILE_OPTIONS "-std=c17;-Wall;-Wextra;-Wpedantic;-Werror")
