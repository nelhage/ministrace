# Warnings from compiling stuff from ext should be ignored (not part of the production code)
# add_compile_options(-Wno-pedantic -Wno-unused-variable -Wno-unused-but-set-variable -Wno-unused-parameter -Wno-missing-field-initializers -Wno-format -Wno-strict-prototypes -Wno-unused-macros -Wno-switch-enum)

add_subdirectory(atomic_hash)
