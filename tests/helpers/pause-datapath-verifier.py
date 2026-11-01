"""Pause only this wrapper's child at its real firewall-control BPF load syscall."""
import ctypes, os, pathlib, signal, sys, time
libc=ctypes.CDLL(None,use_errno=True)
libc.ptrace.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
libc.ptrace.restype=ctypes.c_long
class Registers(ctypes.Structure):
    _fields_=[(name,ctypes.c_ulonglong)for name in 'r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()]
def trace(request,pid,address=0,data=0):
    ctypes.set_errno(0)
    value=libc.ptrace(request,pid,ctypes.c_void_p(address),ctypes.c_void_p(data))
    if value==-1 and ctypes.get_errno():raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
    return value
prefix=pathlib.Path(sys.argv[1]);paused=prefix.with_suffix('.paused');resume=prefix.with_suffix('.resume')
child=os.fork()
if child==0:
    trace(0,0)
    os.kill(os.getpid(),signal.SIGSTOP)
    os.execv(sys.argv[2],sys.argv[2:])
    os._exit(127)
_,status=os.waitpid(child,0)
assert os.WIFSTOPPED(status),status
trace(0x4200,child,0,0x1|0x100000) # TRACESYSGOOD | EXITKILL
entering=True
trace(24,child)
while True:
    _,status=os.waitpid(child,0)
    if os.WIFEXITED(status):sys.exit(os.WEXITSTATUS(status))
    if os.WIFSIGNALED(status):sys.exit(128+os.WTERMSIG(status))
    stop=os.WSTOPSIG(status)
    if stop==(signal.SIGTRAP|0x80):
        regs=Registers();trace(12,child,0,ctypes.addressof(regs))
        if entering and regs.orig_rax==321 and regs.rdi==5: # x86_64 bpf(BPF_PROG_LOAD)
            name=b''.join((trace(2,child,regs.rsi+48+offset)&((1<<64)-1)).to_bytes(8,'little')for offset in (0,8)).split(b'\0',1)[0]
            if name==b'fw_flow_control':
                paused.write_text(str(child))
                print('ACTUAL_VERIFIER_SYSCALL_PAUSED',child,name.decode(),flush=True)
                deadline=time.monotonic()+120
                while not resume.exists():
                    if time.monotonic()>deadline:raise TimeoutError('test did not resume the paused child')
                    time.sleep(.01)
                trace(17,child) # DETACH resumes the real, unmodified agent
                _,status=os.waitpid(child,0)
                sys.exit(os.waitstatus_to_exitcode(status))
        entering=not entering
        trace(24,child)
    else:
        trace(24,child,0,0 if stop==signal.SIGTRAP else stop)
