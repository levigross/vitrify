# Vitrify Documentation

This documentation expands on the README and is intended to be a practical, operator-focused reference.

## Contents

- Overview and layer model
- Version policy
- Getting started
- Paranoia defaults
- Module reference
- Testing and development
- Compatibility notes
- Security model

## Overview

Vitrify is a collection of NixOS modules that harden the kernel, userspace, and integrity layers. The modules are designed to be composable and are exposed under the `vitrify.*` namespace.

### Layer Model

| Layer | Module(s) | Goal |
| --- | --- | --- |
| Kernel | `hardenedKernel` | Strong kernel hardening via Clang, kCFI, LTO, and stricter kernel config. |
| Userspace | `hardenedUserspace` | Sysctls, allocator hardening, attack-surface reduction. |
| Defaults | `paranoia` | Secure defaults that can be overridden. |
| Block integrity | `verity` | dm-verity setup for verified block devices. |
| File integrity | `fsverity` | fs-verity for immutable, verified files. |
| Service sandboxing | `systemdHardening` | Systemd unit hardening profiles. |

## Version Policy

Vitrify tracks the current stable NixOS release and a fixed LTS kernel used by the hardened kernel module.

| Component | Version | Source |
| --- | --- | --- |
| NixOS | 25.11 | `flake.nix` input `nixos-25.11` |
| Linux kernel (hardenedKernel) | 6.12 LTS | `modules/kernel.nix` overlay `linuxPackages_6_12` |

## Getting Started

### Minimal Flake

```nix
{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";
    vitrify.url = "github:levigross/vitrify";
  };

  outputs = { nixpkgs, vitrify, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        vitrify.nixosModules.all
        ./configuration.nix
      ];
    };
  };
}
```

### Optional: Paranoia Defaults

```nix
vitrify.paranoia.level = "balanced"; # or "strict", "paranoid"
```

### Disable Paranoia Defaults

```nix
vitrify.paranoia.enable = false;
```

## Paranoia Defaults

The paranoia module applies hardening defaults via `mkDefault`, so explicit overrides always win. It exists to make the “secure by default” path easy without removing operator control.

### Default Matrix (Summary)

| Category | balanced | strict | paranoid |
| --- | --- | --- | --- |
| Allocator provider | scudo | graphene-hardened-light | graphene-hardened |
| Sysctl set | baseline | baseline + stricter ptrace/perf/mmap | strict + max ptrace/mmap |
| Kernel module blacklist | baseline | baseline + extra hardware | strict + widest surface |
| Systemd hardening profile | base | moderate | strict |
| User namespaces | allow | disable | disable |
| AppArmor and audit | on | on | on |
| Kernel module lock | on | on | on |
| Nix daemon restrictions | wheel-only + sandbox | wheel-only + sandbox | wheel-only + sandbox + no fallback |
| Verity and fs-verity | opt-in | opt-in | opt-in |
| Mount hardening | nosuid on /tmp | nosuid,noexec on /tmp,/var/tmp | strict + nodev on /tmp,/var/tmp |
| Seccomp default | off unless enabled | restrictive preset | strict preset |

### Compatibility Impact (Typical)

- `strict` and `paranoid` disable unprivileged user namespaces. This can break rootless containers and browser sandboxes.
- `noexec` on `/tmp` and `/var/tmp` can break installers or build tooling that execute from tmp.
- Hardened allocators may expose memory bugs in applications.

## Module Reference

### `hardenedKernel`

Builds a Clang/LLVM kernel with kCFI and Thin LTO, and enforces a hardened kernel configuration.

#### Build Features

| Feature | Purpose |
| --- | --- |
| Clang/LLVM toolchain | Consistent modern kernel toolchain. |
| kCFI + Thin LTO | Control-flow integrity across compilation units. |
| LLVM LLD | Hardened and consistent linking path. |

#### Memory Protection

| Config | Effect |
| --- | --- |
| `STACKPROTECTOR_STRONG` | Stack canaries for more functions. |
| `INIT_STACK_ALL_ZERO` | Zero-initialize stack variables. |
| `HARDENED_USERCOPY` | Bounds checks on user copy. |
| `VMAP_STACK` | Guarded, virtually mapped stacks. |
| `INIT_ON_ALLOC_DEFAULT_ON` | Zero on allocation. |
| `INIT_ON_FREE_DEFAULT_ON` | Zero on free. |

#### Slab Allocator Hardening

| Config | Effect |
| --- | --- |
| `SLAB_MERGE_DEFAULT=n` | Prevent cross-cache reuse. |
| `SLAB_FREELIST_RANDOM` | Randomize freelist placement. |
| `SLAB_FREELIST_HARDENED` | Pointer mangling for freelists. |
| `SHUFFLE_PAGE_ALLOCATOR` | Randomize page allocator. |

#### Address Space Randomization

| Config | Effect |
| --- | --- |
| `RANDOMIZE_BASE` | KASLR. |
| `RANDOMIZE_MEMORY` | Randomize physical-to-virtual mapping. |

#### Attack Surface Reduction

| Config | Effect |
| --- | --- |
| `KEXEC=n` | Disable runtime kernel replacement. |
| `HIBERNATION=n` | Disable hibernation. |
| `KGDB=n` | Disable kernel debugger. |
| `DEVPORT=n` | Disable legacy /dev/port. |
| `MODIFY_LDT_SYSCALL=n` | Disable modify_ldt. |
| `LEGACY_VSYSCALL_NONE` | Disable legacy vsyscall page. |

#### Security Modules and Integrity

| Config | Effect |
| --- | --- |
| `SECURITY_LOCKDOWN_LSM` | Kernel lockdown mode. |
| `SECURITY_APPARMOR` | AppArmor enforcement. |
| `MODULE_SIG_FORCE` | Require signed kernel modules. |
| `MODULE_SIG_SHA512` | SHA-512 signatures. |
| `STRICT_DEVMEM` | Restrict /dev/mem access. |

#### dm-verity and fs-verity (Built-In)

| Config | Effect |
| --- | --- |
| `DM_VERITY` | dm-verity support. |
| `DM_VERITY_VERIFY_ROOTHASH_SIG` | Enforce root hash signatures. |
| `DM_VERITY_FEC` | Forward error correction. |
| `FS_VERITY` | fs-verity support. |
| `FS_VERITY_BUILTIN_SIGNATURES` | Built-in fs-verity verification. |

#### Runtime Sanitizers

| Config | Effect |
| --- | --- |
| `UBSAN` | Undefined behavior sanitizer. |
| `UBSAN_TRAP` | Trap on UB. |
| `UBSAN_BOUNDS` | Bounds checking. |

#### Kernel Boot Parameters

| Parameter | Purpose |
| --- | --- |
| `slab_nomerge` | Disable slab merging at runtime. |
| `init_on_alloc=1` | Zero memory on allocation. |
| `init_on_free=1` | Zero memory on free. |
| `page_alloc.shuffle=1` | Randomize page allocator. |
| `lockdown=confidentiality` | Enable strict lockdown. |
| `debugfs=off` | Disable debugfs. |
| `module.sig_enforce=1` | Enforce module signing. |
| `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` | LSM stack order. |

Override example:

```nix
vitrify.kernel.kernelParams.extra = [ "pti=on" ];
vitrify.kernel.kernelParams.remove = [ "debugfs=off" ];
```

### `hardenedUserspace`

Applies userspace hardening without requiring kernel rebuilds. All defaults are under `vitrify.userspace.*` and can be overridden directly.

#### Memory Allocator

The default allocator is selected by the paranoia level. Hardened allocators can expose latent bugs in some software; override when necessary.

```nix
vitrify.userspace.memoryAllocator.provider = "libc";
```

#### Sysctl Hardening (Selected Defaults)

| Sysctl | Value | Purpose |
| --- | --- | --- |
| `kernel.io_uring_disabled` | 2 | Disable io_uring for unprivileged users. |
| `kernel.dmesg_restrict` | 1 | Restrict dmesg access. |
| `kernel.kptr_restrict` | 2 | Hide kernel pointers. |
| `kernel.unprivileged_bpf_disabled` | 1 | Disable unprivileged BPF. |
| `kernel.yama.ptrace_scope` | 2 | Restrict ptrace. |
| `fs.protected_symlinks` | 1 | Restrict symlink following. |
| `fs.protected_hardlinks` | 1 | Restrict hardlinks. |
| `fs.protected_fifos` | 2 | Restrict FIFO access. |
| `fs.protected_regular` | 2 | Restrict regular file access. |
| `fs.suid_dumpable` | 0 | Disable SUID core dumps. |
| `net.ipv4.conf.all.rp_filter` | 1 | Anti-spoofing. |
| `net.ipv4.conf.all.accept_redirects` | 0 | Disable ICMP redirects. |
| `net.ipv4.conf.all.accept_source_route` | 0 | Disable source routing. |
| `net.ipv4.tcp_syncookies` | 1 | SYN flood protection. |
| `net.ipv4.tcp_rfc1337` | 1 | TIME-WAIT protection. |
| `net.core.bpf_jit_harden` | 2 | Harden BPF JIT. |

Override example:

```nix
vitrify.userspace.sysctl.overrides."kernel.yama.ptrace_scope" = 1;
```

#### Blacklisted Kernel Modules

Vitrify blacklists a baseline set of unused or high-risk modules (uncommon filesystems, niche hardware interfaces, and legacy protocols). You can add or remove entries:

```nix
vitrify.userspace.blacklistedKernelModules.extra = [ "bluetooth" ];
vitrify.userspace.blacklistedKernelModules.remove = [ "erofs" ];
```

#### Permission Hardening

| Setting | Value | Purpose |
| --- | --- | --- |
| Default umask | `0077` | Restrict default file permissions. |
| `security.sudo.execWheelOnly` | `true` | Only wheel group can use sudo. |
| `security.unprivilegedUsernsClone` | `false` | Disable unprivileged user namespaces. |

#### Nix Daemon Security (Defaults)

| Setting | Value | Purpose |
| --- | --- | --- |
| `allowed-users` | `@wheel` | Restrict Nix usage. |
| `trusted-users` | `@wheel` | Restrict trusted users. |
| `sandbox` | `true` | Enforce build sandboxing. |
| `sandbox-fallback` | `false` | Fail if sandbox unavailable. |

### `verity` (dm-verity)

dm-verity verifies block devices using a Merkle tree and a trusted root hash. This protects entire partitions or images against tampering.

#### Device Options

| Option | Type | Required | Description |
| --- | --- | --- | --- |
| `dataDevice` | string | yes | Data device to verify. |
| `hashDevice` | string | yes | Hash device containing the tree. |
| `hashOffset` | int or null | no | Offset if hash is appended. |
| `rootHash` | string | yes | Root hash (hex). |
| `signatureVerification` | bool | no | Verify root hash signature (default: true). |
| `signaturePath` | string | no | Path to PKCS#7 signature. |
| `fecDevice` | string or null | no | Forward error correction device. |
| `fecRoots` | int or null | no | FEC parity bytes. |
| `mountPoint` | string or null | no | Mount point (read-only). |

#### Example

```nix
vitrify.verity = {
  enable = true;
  trustedKeys = [ ./keys/verity-signing.der ];

  devices.data = {
    dataDevice = "/dev/disk/by-partlabel/data";
    hashDevice = "/dev/disk/by-partlabel/data";
    hashOffset = 1073741824;
    rootHash = "4392712ba01368efdf14b05c76f9e4df0d53664630b5d48632ed17a137f39076";
    signaturePath = "/etc/verity-signatures/data.p7s";
    mountPoint = "/mnt/verified";
  };
};
```

#### Creating Verity Images

```bash
# Separate hash device
veritysetup format /dev/sdX1 /dev/sdX2

# Or append hash to data device
veritysetup format /dev/sdX1 /dev/sdX1 --hash-offset=$((1024*1024*1024))
```

#### Root Filesystem Verity

Using dm-verity for the root filesystem requires initrd changes and a read-only root. This is an advanced setup and should be planned alongside your boot chain, key management, and rollback strategy.

### `fsverity`

fs-verity provides integrity protection at the file level. Once enabled on a file, it becomes immutable and verified on read.

#### dm-verity vs fs-verity

| Feature | dm-verity | fs-verity |
| --- | --- | --- |
| Scope | Entire block device | Individual files |
| Use case | OS images, root fs | Configs, binaries, Nix store |
| Flexibility | Fixed at image creation | Can be applied selectively |
| Filesystem | Any | ext4, f2fs, btrfs (with verity feature) |

#### Core Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `enable` | bool | false | Enable fs-verity module. |
| `protectedPaths` | list of strings | `[]` | Files/directories to protect. |
| `verifyOnRead` | bool | true | Verify contents on each read. |

#### Nix Store Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `nixStore.enable` | bool | false | Enable /nix/store protection. |
| `nixStore.autoDetect` | bool | false | Enable only if Nix is unavailable or store is read-only. |
| `nixStore.excludePatterns` | list | `[]` | `find -name` patterns to exclude. |

#### Signature Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `signatureVerification.enable` | bool | false | Require valid signatures. |
| `signatureVerification.trustedCerts` | list of paths | `[]` | Certificates to trust. |
| `signatureVerification.signingKey` | path or null | null | Private key for auto-sign. |
| `signatureVerification.signingCert` | path or null | null | Certificate for auto-sign. |

#### Example: Protect Sensitive Files

```nix
vitrify.fsverity = {
  enable = true;
  protectedPaths = [
    "/etc/ssh/sshd_config"
    "/etc/sudoers"
    "/etc/pam.d"
  ];
};
```

#### Example: Protect the Nix Store

```nix
vitrify.fsverity = {
  enable = true;
  nixStore = {
    enable = true;
    autoDetect = true;
    excludePatterns = [ "*.drv" "*.lock" ];
  };
};
```

### `systemdHardening`

Applies systemd service sandboxing presets. This reduces blast radius for compromised services.

#### Profiles

| Profile | Security level | Compatibility | Use case |
| --- | --- | --- | --- |
| `strict` | maximum | low | minimal services, high-security systems |
| `base` | high | medium | recommended default |
| `moderate` | medium | high | general purpose |
| `minimal` | basic | very high | compatibility-focused |

#### Key Options

| Option | Purpose |
| --- | --- |
| `hardenedServices` | List of services to harden. |
| `exemptServices` | Services that keep their original config. |
| `networkServices` | Services exempt from IP restrictions. |
| `privilegedServices` | Services that need elevated privileges. |
| `customOverrides` | Per-service overrides. |
| `globalOverrides` | Overrides for all hardened services. |
| `profileOverrides` | Override built-in presets per profile. |
| `user.enable` | Apply hardening to user services. |

#### Example

```nix
vitrify.systemdHardening = {
  enable = true;
  profile = "base";

  hardenedServices = [
    "nginx"
    "sshd"
    "postgresql"
  ];

  networkServices = [
    "nginx"
    "sshd"
    "postgresql"
  ];

  customOverrides.nginx = {
    ProtectHome = false;
    ReadWritePaths = [ "/var/www" ];
  };
};
```

## Testing and Development

### Using Just

| Command | Purpose |
| --- | --- |
| `just` | List available tasks. |
| `just check-fast` | Evaluation checks only (no VMs). |
| `just check` | Full matrix including VM tests. |
| `just test-userspace` | Userspace hardening tests. |
| `just test-paranoia-balanced` | Paranoia balanced tests. |
| `just test-paranoia-strict` | Paranoia strict tests. |
| `just test-paranoia-paranoid` | Paranoia paranoid tests. |
| `just test-verity` | dm-verity tests. |
| `just test-fsverity` | fs-verity tests. |
| `just test-systemd` | systemd hardening tests. |
| `just test-full` | Full config boot test. |

### Using Nix Directly

```bash
nix flake check
nix build .#checks.x86_64-linux.userspace -L
nix flake show
```

### Formatting

```bash
just fmt
just fmt-check
```

## Compatibility Notes

- Kernel module signing is enforced, so unsigned third-party modules require signing.
- Unprivileged user namespaces may be disabled in strict profiles; this affects rootless containers and some browser sandboxes.
- Hardened memory allocators can surface application bugs.
- fs-verity makes files immutable; plan for lifecycle and updates.
- dm-verity root requires a read-only root, initrd work, and careful key management.

## Security Model

| Vitrify helps with | Vitrify does not solve |
| --- | --- |
| Kernel exploit hardening | Application vulnerabilities |
| Reducing attack surface | Physical access (use FDE + Secure Boot) |
| Integrity of OS images | Supply-chain trust (verify inputs) |
| Preventing file tampering | Social engineering attacks |
