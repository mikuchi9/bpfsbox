# 🚧 Upcoming: SafeSetID-BPF (working name)

A small eBPF-based sandboxing tool designed to block any attempt by a process—or its descendants—to escalate to root with **setuid(0) / setresuid(0,0,0) / setreuid(0,0)**.

- Focus: runtime privilege-escalation control, complementary to seccomp.
- Deploy: load once, attach per-process; no code changes needed in the target app.
- Visibility: every denied attempt is emitted.
- Status: in progress, repo to be published after initial verifier clean-pass.
