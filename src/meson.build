rw_files = files('lib.cpp', 'main.cpp', 'plugin.cpp')
rw_incs = []
rw_deps = []
cc = meson.get_compiler('cpp')
amd64 = target_machine.cpu_family() == 'x86_64'
subdir('hook')
subdir('plugins')

shared_module(
	'ResourceWrapper', [rw_files, hook_files],
	include_directories: rw_incs,
	dependencies: rw_deps,
	vs_module_defs: 'lib.def',
)