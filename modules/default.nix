# Vitrify NixOS Modules
#
# A collection of security hardening modules for NixOS.
# Import individual modules or use 'all' for the complete hardening profile.
{
  # Individual modules
  hardenedKernel = ./kernel.nix;
  hardenedUserspace = ./userspace.nix;
  paranoia = ./paranoia.nix;
  verity = ./verity.nix;
  fsverity = ./fsverity.nix;
  systemdHardening = ./systemd-hardening.nix;

  # Combined module that enables all hardening
  # Note: verity/fsverity/systemdHardening require explicit configuration
  # so they're imported but not enabled by default
  all =
    { ... }:
    {
      imports = [
        ./paranoia.nix
        ./kernel.nix
        ./userspace.nix
        ./verity.nix
        ./fsverity.nix
        ./systemd-hardening.nix
      ];
    };
}
