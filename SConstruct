opts=Options()

opts.Add(BoolOption('PROFILE', 'Compile with profiling.', 0))
opts.Add(BoolOption('USE_ASSERT', 'Compile with assertions', 0))

env = Environment(options = opts)
Help(opts.GenerateHelpText(env))

# Extra places we need to look for includes
env.Append(CPPPATH = ['/opt/local/include', '/usr/local/include'])
env.Append(LIBPATH = ['/opt/local/lib', '/usr/local/lib'])

if ARGUMENTS.get('USE_ASSERT', 0):
	env.Append(CCFLAGS = '-DUSE_ASSERT=1')

env.Append(CCFLAGS = '-g -Wall -Werror')
env.Append(LINKFLAGS = '-g')

if ARGUMENTS.get('PROFILE', 0):
	env.Append(CCFLAGS = '-pg')
	env.Append(LINKFLAGS = '-pg')
else:
	# Turn on tons of optimization if we're not profiling.
	env.Append(CCFLAGS = '-O3')

env.conf = Configure(env)

if not env.conf.CheckLibWithHeader('pcap', 'pcap.h', 'c'):
	print 'pcap is required'
	Exit(1)

if env.conf.CheckFunc('pcap_dump_flush'):
	env.Append(CCFLAGS = '-DHAVE_PCAP_DUMP_FLUSH=1')
else:
	print "pcap_dump_flush isn't defined.  Consider upgrading pcap."

env = env.conf.Finish()
env.Program('multisniff', ['main.c', 'filter.c', 'hash.c', 'mymalloc.c'],
	LIBS=['pcap'])

# vim: syntax=python
