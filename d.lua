-- demonstration and ad-hoc testing of ldb api

-- attach to a particular process id
-- ldb.attach(99106);
ldb.attach(29633);

-- iterate the threads
local threads = ldb.threads;
for thr in threads do
	print("thread", thr);
	local frames = thr.frames;
	print("frames:", frames)
	-- iterate the frames
	for f in frames do
		print("frame", f);
		print("  up", f.up);
		print("  down", f.down);
		print("  pc", f.pc);
		print("  is_signal", f.is_signal);
		print("  signo", f.signo);
		print("  signame", f.signame);
		print("  file", f.file);
		print("  line", f.line);
		print("  label", f.label);
		local vars = f.vars;
		for varname, isparam, var in vars do
			print("var", varname, isparam, var.ctype, var.tag, var.typename, var.addr);
			if var.tag == "pointer" and varname == "si" then
				print("deref pointer");
				local ref = var.deref;
				print("deref", ref.ctype, ref.tag, ref.typename, ref.addr);
			end
			if varname == "signo" then
				local val = var.value;
				print("signo value is", val);
			end
		end
		local signo = vars.signo;
		if signo then
			print("resolve var signo", signo, signo.ctype);
		end
	end
	print("now trying to index frame 0");
	print(frames[0]);
	print("now trying to index frame 1");
	print(frames[1]);
end
print("now trying to index thread 0");
print(threads[0]);
print("now trying to index thread 1");
print(threads[1]);

