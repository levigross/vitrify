# MODULE: Userspace Sysctl Hardening
{
  config,
  lib,
  ...
}:
let
  cfg = config.vitrify.userspace.sysctl;

  baseSysctls = {
    # Disable io_uring (attack surface reduction)
    "kernel.io_uring_disabled" = 2;

    # Filesystem hardening
    "fs.protected_fifos" = 2;
    "fs.protected_hardlinks" = 1;
    "fs.protected_regular" = 2;
    "fs.protected_symlinks" = 1;
    "fs.suid_dumpable" = 0;

    # Kernel pointer and debug restrictions
    "kernel.dmesg_restrict" = 1;
    "kernel.kptr_restrict" = 2;
    "kernel.unprivileged_bpf_disabled" = 1;
    "kernel.yama.ptrace_scope" = 2;

    # BPF JIT hardening
    "net.core.bpf_jit_harden" = 2;

    # IPv4 network hardening
    "net.ipv4.conf.all.accept_redirects" = 0;
    "net.ipv4.conf.all.accept_source_route" = 0;
    "net.ipv4.conf.all.log_martians" = 1;
    "net.ipv4.conf.all.rp_filter" = 1;
    "net.ipv4.conf.all.secure_redirects" = 0;
    "net.ipv4.conf.all.send_redirects" = 0;
    "net.ipv4.conf.default.accept_redirects" = 0;
    "net.ipv4.conf.default.accept_source_route" = 0;
    "net.ipv4.conf.default.rp_filter" = 1;
    "net.ipv4.conf.default.secure_redirects" = 0;
    "net.ipv4.conf.default.send_redirects" = 0;
    "net.ipv4.icmp_echo_ignore_broadcasts" = 1;
    "net.ipv4.tcp_rfc1337" = 1;
    "net.ipv4.tcp_syncookies" = 1;

    # IPv6 network hardening
    "net.ipv6.conf.all.accept_redirects" = 0;
    "net.ipv6.conf.all.accept_source_route" = 0;
    "net.ipv6.conf.default.accept_redirects" = 0;
    "net.ipv6.conf.default.accept_source_route" = 0;
  };

  effectiveDefaults = lib.recursiveUpdate baseSysctls cfg.defaults;

  sysctlDefaults = lib.mapAttrs (_: value: lib.mkOverride 900 value) effectiveDefaults;
  sysctlOverrides = lib.mapAttrs (_: value: lib.mkForce value) cfg.overrides;
in
{
  options.vitrify.userspace.sysctl = {
    defaults = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.oneOf [
          lib.types.int
          lib.types.str
        ]
      );
      default = { };
      description = ''
        Default sysctl values applied by Vitrify. These are merged on top of
        the built-in baseline and can be adjusted per paranoia level.
      '';
    };

    overrides = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.oneOf [
          lib.types.int
          lib.types.str
        ]
      );
      default = { };
      description = ''
        Explicit sysctl overrides applied after defaults. Use this to tweak or
        replace individual values without disabling the hardening profile.
      '';
    };
  };

  config = {
    boot.kernel.sysctl = lib.mkMerge [
      sysctlDefaults
      sysctlOverrides
    ];
  };
}
