# bpfsbox

**bpfsbox** is a minimal eBPF-based sandbox enforcement tool that monitors and restricts privilege escalation syscalls (e.g. `setuid()`, `setreuid()`, `setresuid()`) by killing processes that violate sandbox rules. It uses Linux cgroups and eBPF tracepoints to provide lightweight, in-kernel process isolation and monitoring.

---

### ✨ Features

- Monitors syscalls: `setuid()`, `setreuid()`, `setresuid()` using eBPF tracepoints.
- Restricts privilege elevation for processes in specified cgroups.
- Kills offending processes automatically from inside the kernel.
- No need for userland context-switching or polling.
- Written in C using `libbpf`.

---

### 📦 Prerequisites

- Linux kernel with eBPF support
- Clang/LLVM and libbpf-dev
- bpftool
- Root privileges
- cgroup v2

---

### 🧠 How It Works

1. The parent process is placed into a dedicated cgroup.
2. All child processes inherit the cgroup.
3. A pinned eBPF map stores the cgroup ID.
4. An eBPF program is attached to syscall tracepoints: `sys_enter_setuid`, `sys_enter_setreuid`, `sys_enter_setresuid`.
5. When a monitored syscall is triggered, the BPF program:
   - Checks if the process is in the target cgroup.
   - If so, it kills the process immediately using `bpf_send_signal(SIGKILL)`.

---

### 🛠️ Build and Run

```
make all
sudo ./bpfsbox <cgroup_name> <process_pid>
```
### 🧪 Example Usage

Run your program with:
`sudo ./bpfsbox <cgroup_name> <process_pid> &`
This will:
- Create a new cgroup under `/sys/fs/cgroup/<cgroup_name>/`
- Add the specified `process_pid` to the new cgroup by writing it to `cgroup.procs`

To manually add other processes (not descendants of the initial one) to the same sandboxed group:
`echo <other_process_pid> | sudo tee /sys/fs/cgroup/<cgroup_name>/cgroup.procs`.
You can also daemonize `bpfsbox`.

### 🧪 Simulated Privilege Escalation
> A helper program's source code, `setuid.c`, is included to simulate privilege escalation using `setuid()`. When run inside the sandboxed cgroup, your eBPF program detects and kills it using `bpf_send_signal(SIGKILL)`.

🔍 This helps validate that the sandbox logic correctly intercepts and handles dangerous system calls.

### 🧾 Header provenance
The bundled `vmlinux.h` was generated on Ubuntu 22.04.04 LTS (kernel 6.5.0, BTF enabled)
using `bpftool v7.3.0`. Regenerate with `make headers` if you need an exact match
for a custom kernel.
