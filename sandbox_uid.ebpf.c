#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <errno.h>

#define MAX_RETRY_KILL  5

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} cgroup_id_map SEC(".maps");

__u64 cgroup_id = 0;

static __always_inline void kill_child(const char *syscall_name, __u32 *pid) {

    bpf_printk("%s syscall. Process %lu tried to elevate the privileges", syscall_name, *pid);
    long res = bpf_send_signal(9); // SIGKILL = 9

    if (res == 0) {
        bpf_printk("The kernel queued it to kill. Maybe you already seen the result, that it was killed...\n", *pid);
    } else {
        char *kerror_info; 
        if (res == -EBUSY)
            kerror_info = " because the NMI queue was full";
        if (res == -EPERM)
            kerror_info = " because of insufficient privileges";
        if (res == -EAGAIN)
            kerror_info = "";
        
        bpf_printk("The kernel tried to kill it but failed%s, it will try again\n", kerror_info);
        
        for (int i = 0; i < MAX_RETRY_KILL; i++) {
            res = bpf_send_signal(9); // SIGKILL = 9
            if (res == 0)
                break;
        }
    }

    if (res)
        bpf_printk("The kernel tried %d times to kill the process, but failed! KILL it manually\n", MAX_RETRY_KILL);
    else
        bpf_printk("The kernel queued it to kill. Maybe you already saw the result, that it was killed...\n", *pid);
}

static __always_inline void get_cgroup_id(const char *caller) {
    if (cgroup_id == 0) {
        __u32 e = 0;
        __u64 *cgd = bpf_map_lookup_elem(&cgroup_id_map, &e);
        if (cgd) {
            cgroup_id = *cgd;
        }
    }
}

SEC("tracepoint/syscalls/sys_enter_setuid") // setuid - set user identity
int block_setuider(struct trace_event_raw_sys_enter *ctx) {
    
    // get cgroup_id from the map and save it in cgroup_id global variable if it is not already saved there
    get_cgroup_id("setuid()");

    __u64 c_cgroup_id = bpf_get_current_cgroup_id();
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u32 pid = pid_tgid >> 32;
    
    if (c_cgroup_id == cgroup_id) {
        bpf_printk("this process is a sandboxed process!\n");
        kill_child("setuid()", &pid);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setreuid") // set real and/or effective user ID
int block_setreuider(struct trace_event_raw_sys_enter *ctx) {
    
    // get cgroup_id from the map and save it in cgroup_id global variable if it is not already saved there
    get_cgroup_id("setreuid()");
    
    __u64 c_cgroup_id = bpf_get_current_cgroup_id();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    __u32 pid = pid_tgid >> 32;

    if (c_cgroup_id == cgroup_id) {
        bpf_printk("this process is a sandboxed process!\n");
        kill_child("setreuid()", &pid);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setreuid") // set real, effective, and saved user ID
int block_setresuider(struct trace_event_raw_sys_enter *ctx) {
    
    // get cgroup_id from the map and save it in cgroup_id global variable if it is not already saved there
    get_cgroup_id("setresuid()");
    
    __u64 c_cgroup_id = bpf_get_current_cgroup_id();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    
    __u32 pid = pid_tgid >> 32;

    if (c_cgroup_id == cgroup_id) {
        bpf_printk("this process is a sandboxed process!\n");
        kill_child("setresuid()", &pid);
    }
        
    return 0;
}

char LICENSE[] SEC("license") = "GPL";