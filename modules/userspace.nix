# MODULE: Hardened Userspace Defaults
#
# Provides comprehensive userspace hardening including:
# - Hardened memory allocator
# - Restrictive sysctl settings
# - Blacklisted insecure kernel modules
# - Strict umask and permission defaults
# - Security frameworks (AppArmor, audit)
# - Mount hardening for temporary filesystems
{
  ...
}:
{
  imports = [
    ./userspace/memory-allocator.nix
    ./userspace/sysctl.nix
    ./userspace/blacklist.nix
    ./userspace/permissions.nix
    ./userspace/systemd-defaults.nix
    ./userspace/user-namespaces.nix
    ./userspace/nix-daemon.nix
    ./userspace/security-frameworks.nix
    ./userspace/kernel-lockdown.nix
    ./userspace/mount-hardening.nix
  ];
}
