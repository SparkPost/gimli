
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
db.attach(pid);

for thr in db.threads do
	print(thr)
	for f in thr.frames do
		if f.is_signal then
			print(" ** signal handler **")
		else
			print(f.label)
			for varname, isparam, var in f.vars do
				print(varname, isparam, db.type_c(var))
				if varname == "si" then
					print("looking in struct siginfo")
					for k, v in db.deref(var) do
						print("", k, v)
					end
				end
			end
		end
	end
end

posix.kill(pid, 9);

