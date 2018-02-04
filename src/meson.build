conf_data = configuration_data()
conf_data.set('package', 'addrwatch')
conf_data.set('version', '1.0.1')
conf_data.set('bugreport', 'julius.kriukas@gmail.com')
configure_file(input : 'config.h.in',
               output : 'config.h',
               configuration : conf_data)

add_global_arguments('-DHAVE_CONFIG_H', language: 'c')

deps = [
	dependency('libevent', version : '>=2.0'),
	dependency('pcap'),
	meson.get_compiler('c').find_library('rt')
]
srcs = ['addrwatch.c', 'util.c', 'parse.c', 'check.c', 'process.c', 'base64.c', 'storage.c', 'mcache.c', 'output_flatfile.c', 'output_sqlite.c', 'output_shm.c']

executable('addrwatch', sources: srcs , dependencies: deps)
