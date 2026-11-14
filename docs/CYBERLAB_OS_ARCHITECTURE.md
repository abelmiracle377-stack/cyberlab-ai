# CyberLab OS — Architecture and Additive Delivery Plan

## Product decision

CyberLab OS is the unified operating environment for CyberLab AI. It is not initially a new Linux kernel or a replacement for Kali Linux. It is a managed workstation layer that connects the CyberLab AI control plane to local and isolated Linux environments.

The first release must preserve the existing CyberLab AI web application, agent, model workspace, evidence vault, tool pages, local Kali companion, Ollama adapter, pairing flow, telemetry and explicitly authorised assessment workflow.

## Architecture

### 1. CyberLab OS control plane

The existing CyberLab AI application remains the control plane:
- agent coordinator and future specialist delegation;
- model selection, local Ollama and cloud model workspace;
- investigation workspace, evidence provenance and reporting;
- environment inventory, status and resource visibility;
- approval gates for sensitive operations.

The web application does not itself become a Linux kernel, hypervisor or remote shell. It requests bounded operations from a paired local runtime.

### 2. Environment manager

Add an environment manager as a separate, additive subsystem. It should expose a capability/status contract rather than assuming every host supports every runtime.

Initial environment types:
- native-kali: the existing Kali companion and bridge; preserve current endpoints and pairing.
- native-linux: local Linux host capabilities detected by the companion.
- container: optional Podman/Docker-compatible isolated workspaces when installed and explicitly enabled.
- wsl: optional Windows Subsystem for Linux integration when available.
- virtual-machine: later integration with a locally installed hypervisor (QEMU/KVM, VirtualBox, VMware or Hyper-V), detected rather than assumed.

No environment should be provisioned, started, stopped, deleted or granted network access without explicit user action and a clear preview of resource use and scope.

### 3. CyberLab Terminal

Build a Termux-style lightweight terminal experience before full desktop virtualization:
- terminal session UI connected only to a paired local companion;
- explicit command execution, working directory and timeout;
- allowlisted operations first; no unauthenticated or public shell;
- command output and exit status captured as evidence with timestamps;
- no silent command execution by the AI;
- destructive, privileged, network-active or externally impactful commands require an approval step;
- never expose the bridge beyond loopback by default.

The terminal must be a new capability, not a replacement for the existing AI chat or Kali scan page.

### 4. Linux environment profiles

Create profiles, not copied operating systems:
- Kali profile: use the user's existing Kali installation/companion and preserve its current scan, telemetry and Ollama integrations.
- Ubuntu profile: optional local/container/VM environment for development, cloud and server-security work.
- CyberLab Minimal profile: lightweight base with only selected tools and dependencies.
- CyberLab Security profile: curated security tool groups installed on demand, with licensing and package provenance documented.

Use upstream distributions and package repositories where possible. Do not redistribute Kali, Ubuntu or Parrot images without checking their trademarks, licenses, image terms and redistribution requirements.

### 5. Future CyberLab OS distribution

Only after the environment manager and profiles are reliable should we produce a bootable image. Prefer a reproducible Debian/Ubuntu-derived build with:
- documented package manifest and pinned build inputs;
- signed release artifacts and checksums;
- security updates and rollback strategy;
- hardware/architecture matrix;
- installer/live mode and persistence design;
- clear attribution and license compliance;
- reproducible build pipeline and image verification.

A custom kernel is explicitly not an initial requirement. A branded, reproducible Linux distribution assembled from a maintained upstream base is a much more realistic first OS release.

## Phased implementation

### Phase 0 — Preserve and baseline
- Keep all existing routes, APIs, features and companion endpoints.
- Work only on feat/model-intelligence-workspace.
- No merge to main, production configuration edits or deployment.
- Capture current behavior and test existing companion and web build.

### Phase 1 — OS foundation (first implementation slice)
- Add architecture documentation and an OS capability registry.
- Define environment types, lifecycle states, resource requirements and permission levels.
- Add companion read-only capability discovery for installed runtimes and virtualization support.
- Do not install packages or start VMs during discovery.

### Phase 2 — CyberLab OS workspace
- Add a new /os workspace without changing the current dashboard or Kali connection page.
- Show detected host, supported runtimes, environment profiles and resource headroom.
- Clearly distinguish available, configured, running, unsupported and planned capabilities.
- Keep Kali integration visible as a first-class existing environment.

### Phase 3 — Safe lightweight terminal
- Implement local paired terminal sessions with strict bounds, audit records and approval controls.
- Start with safe read-only diagnostics and explicitly selected commands.
- Add command allowlists and per-command risk classification before broader command execution.
- Do not implement an unrestricted web-to-host shell.

### Phase 4 — Containers and distro profiles
- Add opt-in container runtime integration and reproducible CyberLab Minimal/Kali-compatible/Ubuntu profiles.
- Enforce resource, filesystem and network boundaries.
- Require confirmation before pulling images, mounting host paths, privileged mode or enabling network access.

### Phase 5 — Virtual machines
- Detect available hypervisors and host hardware virtualisation.
- Support importing official Kali/Ubuntu images and later CyberLab images.
- Provide resource previews and explicit start/stop/delete confirmation.
- Keep VM management local; do not attempt to run a hypervisor inside the hosted Next.js app.

### Phase 6 — Bootable CyberLab OS
- Build and sign a reproducible image only after the earlier phases pass tests on supported hardware.
- Maintain upgrade, rollback, image verification and release documentation.

## Safety and compatibility invariants

- Existing Kali bridge endpoints and token pairing remain backward compatible.
- No automatic scans, exploits, package installs, VM lifecycle changes or privileged commands.
- No public listener or remote shell by default.
- Every environment action records actor, target environment, requested operation, approval state, result and timestamp.
- Treat terminal output, files, package metadata and imported VM images as untrusted input.
- Never claim an environment is running unless the local runtime confirms it.
- Low-memory hosts must receive a lightweight profile recommendation; do not assume a full desktop VM is viable.
- The OS workspace must remain useful even when no container runtime or hypervisor is installed.

## Initial acceptance criteria

1. Existing CyberLab AI routes and features remain available.
2. Existing Kali companion tests continue to pass.
3. Capability discovery is read-only and reports unsupported runtimes honestly.
4. A host with no hypervisor can still use the CyberLab OS workspace and existing Kali integration.
5. Environment lifecycle operations are explicit, bounded and auditable.
6. No deployment or production configuration change is part of this work.
