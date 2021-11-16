rw_files += files('convert.cpp', 'plugin.cpp')
rw_incs += include_directories('library/include')

libdir = meson.current_source_dir() + '/library/' + (amd64 ? 'lib64' : 'lib32') 

libflac = cc.find_library('FLAC', dirs: libdir)
rw_deps += libflac

libflacpp = cc.find_library('FLAC++', dirs: libdir)
rw_deps += libflacpp
