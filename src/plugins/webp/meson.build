rw_files += files('convert.cpp', 'plugin.cpp')
rw_incs += include_directories('library/include')

libdir = meson.current_source_dir() + '/library/' + (amd64 ? 'lib64' : 'lib32') 

libwebp = cc.find_library('webp', dirs: libdir)
rw_deps += libwebp

libpng = cc.find_library('png', dirs: libdir)
rw_deps += libpng

zlib = cc.find_library('zlib', dirs: libdir)
rw_deps += zlib