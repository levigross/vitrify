# Vitrify

[![CI](https://github.com/levigross/vitrify/actions/workflows/ci.yml/badge.svg)](https://github.com/levigross/vitrify/actions/workflows/ci.yml)

Vitrify is a set of NixOS hardening modules that aim to reduce attack surface and improve integrity at the kernel, userspace, and storage layers. It is designed for systems where security trade-offs are acceptable and operational compatibility is a conscious choice.

## Why Vitrify

- Defense in depth across kernel, userspace, and integrity verification.
- Declarative NixOS modules with a consistent `vitrify.*` namespace.
- Opt-in integrity tooling (dm-verity and fs-verity) to protect block devices and files.
- A simple paranoia layer that applies secure defaults without blocking overrides.

## Quick Start

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

Optional paranoia defaults:

```nix
vitrify.paranoia.level = "strict";
```

## Modules At A Glance

| Module | Purpose |
| --- | --- |
| `hardenedKernel` | Clang-built kernel with kCFI, LTO, dm-verity/fs-verity support, and hardening config. |
| `hardenedUserspace` | Sysctls, hardened allocator, module blacklists, and restrictive defaults. |
| `paranoia` | Secure defaults layer that uses `mkDefault`, so explicit overrides win. |
| `verity` | dm-verity userspace configuration for verified block devices. |
| `fsverity` | fs-verity userspace configuration for protected files and the Nix store. |
| `systemdHardening` | Systemd service sandboxing presets. |
| `all` / `default` | Aggregates all modules above. |

## Documentation

Extended explanations and reference material live in `docs/`.

- [docs/README.md](docs/README.md) - Architecture, paranoia levels, module reference, testing, and compatibility notes.

## Testing

```bash
nix develop
just check-fast
just check
```

For targeted checks:

```bash
just test-userspace
just test-paranoia-strict
just test-verity
```

## CI Policy (PR Approval)

To prevent untrusted code execution, CI only runs PR workloads after explicit approval.

- PRs run a minimal, no-checkout workflow by default.
- A maintainer must apply the `safe-to-test` label to run CI against PR code.
- Approval is required for forks and first-time contributors.
- The labeled run checks out the PR head SHA with no persisted credentials.

## ISO Example

Vitrify ships an example installer ISO built with the strictest defaults (paranoid paranoia level).

- Build locally: `just iso-strict`
- CI publishes the ISO and a Sigstore bundle signed via GitHub OIDC

## Compatibility Notes (Short)

- Kernel module signing is enforced; unsigned third-party modules will not load.
- Unprivileged user namespaces are disabled in stricter profiles; this can break rootless containers and browser sandboxes.
- Hardened allocators may surface latent memory bugs in applications.
- fs-verity makes files immutable; plan around Nix store and deployment lifecycle.
- dm-verity for root requires initrd work and read-only root setup.

See `docs/README.md` for the full compatibility and threat-model discussion.

## License

See `LICENSE`.
