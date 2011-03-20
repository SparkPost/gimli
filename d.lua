-- demonstration and ad-hoc testing of ldb api

-- attach to a particular process id
ldb.attach(99106);

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

