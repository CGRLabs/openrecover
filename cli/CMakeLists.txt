add_executable(openrecover
  src/main.cpp
  src/commands.cpp
  src/android_cmd.cpp)

target_include_directories(openrecover PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(openrecover PRIVATE openrecover_core CLI11::CLI11)
target_compile_definitions(openrecover PRIVATE OPENRECOVER_VERSION="${PROJECT_VERSION}")
openrecover_set_warnings(openrecover)

add_dependencies(openrecover adb_sidecar_policy)

add_custom_command(TARGET openrecover POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          "${PROJECT_SOURCE_DIR}/profiles" "$<TARGET_FILE_DIR:openrecover>/profiles"
  COMMAND ${CMAKE_COMMAND} -E make_directory
          "$<TARGET_FILE_DIR:openrecover>/tools/adb_sidecar"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${PROJECT_SOURCE_DIR}/tools/adb_sidecar/sidecar.py"
          "$<TARGET_FILE_DIR:openrecover>/tools/adb_sidecar/sidecar.py"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${OPENRECOVER_SIDECAR_POLICY_JSON}"
          "$<TARGET_FILE_DIR:openrecover>/tools/adb_sidecar/policy.json"
  COMMENT "Staging profiles and the adb sidecar next to the CLI")

include(GNUInstallDirs)
install(TARGETS openrecover RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY "${PROJECT_SOURCE_DIR}/profiles/"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/openrecover/profiles")
install(FILES "${PROJECT_SOURCE_DIR}/tools/adb_sidecar/sidecar.py"
              "${PROJECT_SOURCE_DIR}/tools/adb_sidecar/policy.py"
              "${OPENRECOVER_SIDECAR_POLICY_JSON}"
        DESTINATION "${CMAKE_INSTALL_BINDIR}/tools/adb_sidecar")
