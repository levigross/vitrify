# Vitrify - NixOS Security Hardening Modules
# Run 'just' to see available commands

# Default: show available commands
default:
    @just --list

# Run all checks (config eval + VM tests)
check:
    nix flake check

# Run only fast config evaluation checks (no VMs)
check-fast:
    nix build .#checks.x86_64-linux.userspaceConfigEval --no-link
    nix build .#checks.x86_64-linux.kernelConfigEval --no-link
    nix build .#checks.x86_64-linux.verityConfigEval --no-link
    nix build .#checks.x86_64-linux.fsverityConfigEval --no-link
    nix build .#checks.x86_64-linux.systemdHardeningConfigEval --no-link
    nix build .#checks.x86_64-linux.allConfigEval --no-link
    nix build .#checks.x86_64-linux.paranoiaBalancedConfigEval --no-link
    nix build .#checks.x86_64-linux.paranoiaStrictConfigEval --no-link
    nix build .#checks.x86_64-linux.paranoiaParanoidConfigEval --no-link
    nix build .#checks.x86_64-linux.paranoiaOverrideConfigEval --no-link

# Run userspace VM test
test-userspace:
    nix build .#checks.x86_64-linux.userspace --no-link -L

# Run verity VM test
test-verity:
    nix build .#checks.x86_64-linux.verity --no-link -L

# Run fsverity VM test
test-fsverity:
    nix build .#checks.x86_64-linux.fsverity --no-link -L

# Run systemd hardening VM test
test-systemd:
    nix build .#checks.x86_64-linux.systemdHardening --no-link -L

# Run full config VM test
test-full:
    nix build .#checks.x86_64-linux.fullConfig --no-link -L

# Run paranoia VM tests
test-paranoia-balanced:
    nix build .#checks.x86_64-linux.paranoiaBalanced --no-link -L

test-paranoia-strict:
    nix build .#checks.x86_64-linux.paranoiaStrict --no-link -L

test-paranoia-paranoid:
    nix build .#checks.x86_64-linux.paranoiaParanoid --no-link -L

# Run all VM tests
test-all: test-userspace test-paranoia-balanced test-paranoia-strict test-paranoia-paranoid test-verity test-fsverity test-systemd test-full

# Build strictest ISO image (paranoid defaults)
iso-strict:
    nix build .#isoStrict -L

# Format all nix files
fmt:
    nixfmt .

# Check formatting without modifying
fmt-check:
    nixfmt --check .

# Show flake outputs
show:
    nix flake show

# Update flake inputs
update:
    nix flake update

# Enter development shell
dev:
    nix develop

# Build a specific check and print store path
build check:
    nix build .#checks.x86_64-linux.{{check}}

# Evaluate a module config (useful for debugging)
eval-config module:
    nix eval .#checks.x86_64-linux.{{module}}ConfigEval --raw

# Run VM test interactively (for debugging)
test-interactive test:
    nix build .#checks.x86_64-linux.{{test}}.driverInteractive --no-link
    $(nix path-info .#checks.x86_64-linux.{{test}}.driverInteractive)/bin/nixos-test-driver
