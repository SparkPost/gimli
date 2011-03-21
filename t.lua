
function spawn(...)
	local pid = posix.fork();
	if pid == 0 then
		posix.execp(...)
		os.exit(1)
	end
	return pid
end

pid = spawn("./wedgie");

print("Running wedgie, waiting for it to wedge");

posix.sleep(4);

print("Attaching to pid", pid);
ldb.attach(pid);

for thr in ldb.threads do
	print(thr)
	for f in thr.frames do
		if f.is_signal then
			print(" ** signal handler **")
		else
			print(f.label)
			for varname, isparam, var in f.vars do
				print(varname, isparam, var.ctype)
			end
		end
	end
end

posix.kill(pid, 9);

