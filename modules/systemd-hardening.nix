# MODULE: Systemd Service Hardening
#
# Applies security hardening defaults to systemd services, reducing the
# attack surface by isolating services and restricting their capabilities.
#
# Hardening is applied at three levels:
# 1. System-wide defaults for all system services
# 2. User session defaults for user services
# 3. Per-service overrides for specific requirements
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.vitrify.systemdHardening;

  # Common hardening options that work for most services
  baseHardening = {
    # Filesystem isolation
    PrivateTmp = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    ProtectProc = "invisible";
    ProcSubset = "pid";

    # Kernel protection
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;

    # Privilege restrictions
    NoNewPrivileges = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;

    # Capability restrictions
    CapabilityBoundingSet = "";
    AmbientCapabilities = "";

    # Device access
    PrivateDevices = true;
    DevicePolicy = "closed";

    # Memory protection
    MemoryDenyWriteExecute = true;

    # Networking (restrictive by default)
    RestrictAddressFamilies = [
      "AF_UNIX"
      "AF_INET"
      "AF_INET6"
    ];
    IPAddressDeny = "any";

    # Namespace restrictions
    RestrictNamespaces = true;

    # Realtime and scheduling
    RestrictRealtime = true;

    # System call filtering
    SystemCallArchitectures = "native";
    SystemCallFilter = [
      "@system-service"
      "~@privileged"
      "~@resources"
    ];
  };

  # Strict hardening - maximum security, may break some services
  strictHardening = baseHardening // {
    ProtectSystem = "strict";
    ProtectHome = "read-only";
    PrivateNetwork = true;
    PrivateUsers = true;
    SystemCallFilter = [
      "@system-service"
      "~@privileged"
      "~@resources"
      "~@mount"
      "~@clock"
      "~@cpu-emulation"
      "~@debug"
      "~@keyring"
      "~@module"
      "~@obsolete"
      "~@raw-io"
      "~@reboot"
      "~@swap"
    ];
    RestrictNamespaces = "~user ~pid ~net ~uts ~mnt ~cgroup ~ipc";
    UMask = "0077";
  };

  # Moderate hardening - good security with broader compatibility
  moderateHardening = baseHardening // {
    ProtectSystem = "full";
    ProtectHome = true;
    PrivateNetwork = false;
    IPAddressDeny = "";
    SystemCallFilter = [
      "@system-service"
      "~@privileged"
    ];
  };

  # Minimal hardening - basic protections only
  minimalHardening = {
    NoNewPrivileges = true;
    PrivateTmp = true;
    ProtectSystem = "full";
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectControlGroups = true;
    RestrictSUIDSGID = true;
  };

  # Select hardening profile
  profileBase =
    if cfg.profile == "strict" then
      strictHardening
    else if cfg.profile == "moderate" then
      moderateHardening
    else if cfg.profile == "minimal" then
      minimalHardening
    else
      baseHardening;

  profileOverride = cfg.profileOverrides.${cfg.profile} or { };

  hardeningProfile = lib.mkMerge [
    profileBase
    profileOverride
    cfg.globalOverrides
  ];

  # Generate service overrides
  mkServiceOverride = name: settings: lib.nameValuePair name { serviceConfig = settings; };

  # User service hardening (subset that works in user context)
  userHardening = {
    PrivateTmp = true;
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = cfg.user.memoryDenyWriteExecute;
    RestrictRealtime = true;
    SystemCallArchitectures = "native";
  };
in
{
  options.vitrify.systemdHardening = {
    enable = lib.mkEnableOption "systemd service hardening";

    profile = lib.mkOption {
      type = lib.types.enum [
        "strict"
        "moderate"
        "minimal"
        "base"
      ];
      default = "base";
      description = ''
        Hardening profile to apply:
        - strict: Maximum security, may require exemptions for some services
        - moderate: Good security with broader compatibility
        - minimal: Basic protections only
        - base: Balanced defaults (recommended starting point)
      '';
    };

    exemptServices = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        List of service names to exempt from hardening.
        These services will use their original configurations.
      '';
      example = [
        "docker"
        "libvirtd"
        "postgresql"
      ];
    };

    customOverrides = lib.mkOption {
      type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
      default = { };
      description = ''
        Custom hardening overrides for specific services.
        Allows fine-tuning individual service security settings.
      '';
      example = lib.literalExpression ''
        {
          nginx = {
            ProtectHome = false;
            ReadWritePaths = [ "/var/www" ];
          };
          postgresql = {
            ProtectSystem = "full";
            ReadWritePaths = [ "/var/lib/postgresql" ];
          };
        }
      '';
    };

    globalOverrides = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = { };
      description = ''
        Additional serviceConfig settings applied to all hardened services,
        regardless of profile. These are merged on top of the selected profile.
      '';
      example = lib.literalExpression ''
        {
          ProtectClock = true;
          RestrictAddressFamilies = [ "AF_UNIX" ];
        }
      '';
    };

    profileOverrides = lib.mkOption {
      type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
      default = { };
      description = ''
        Per-profile overrides applied on top of the built-in hardening presets.
        Keys should be one of: strict, moderate, minimal, base.
      '';
      example = lib.literalExpression ''
        {
          strict = { PrivateNetwork = false; };
          base = { MemoryDenyWriteExecute = false; };
        }
      '';
    };

    user = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Apply hardening to user systemd services as well.
          This affects services started via systemd --user.
        '';
      };

      memoryDenyWriteExecute = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Enable MemoryDenyWriteExecute for user services.
          May break JIT-compiled applications (browsers, IDEs, etc.).
        '';
      };

      hardenedServices = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = ''
          List of user services to apply hardening to.
        '';
        example = [
          "pipewire"
          "dbus"
        ];
      };
    };

    networkServices = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Services that require network access.
        These will have network restrictions relaxed.
      '';
      example = [
        "nginx"
        "sshd"
        "postgresql"
      ];
    };

    privilegedServices = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Services that require elevated privileges.
        These will have capability and syscall restrictions relaxed.
      '';
      example = [
        "docker"
        "libvirtd"
        "systemd-networkd"
      ];
    };

    hardenedServices = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        List of services to apply hardening to.
        Since NixOS cannot automatically apply defaults to all services without
        causing recursion, you must explicitly list services to harden.

        Tip: Use `systemctl list-units --type=service` to see running services.
      '';
      example = [
        "nginx"
        "sshd"
        "postgresql"
        "nix-daemon"
      ];
    };
  };

  config = lib.mkIf cfg.enable {
    # Use serviceConfig defaults that apply to all services without causing recursion
    # This uses the options system properly by setting defaults
    systemd.services = lib.mkMerge [
      # Network service relaxations
      (lib.listToAttrs (
        map (name: mkServiceOverride name { IPAddressDeny = lib.mkForce ""; }) cfg.networkServices
      ))

      # Privileged service relaxations
      (lib.listToAttrs (
        map (
          name:
          mkServiceOverride name {
            CapabilityBoundingSet = lib.mkForce null;
            SystemCallFilter = lib.mkForce [ ];
            PrivateDevices = lib.mkForce false;
            ProtectKernelModules = lib.mkForce false;
          }
        ) cfg.privilegedServices
      ))

      # Custom per-service overrides (highest priority)
      (lib.mapAttrs' (
        name: settings: lib.nameValuePair name { serviceConfig = lib.mkForce settings; }
      ) cfg.customOverrides)

      # Apply hardening to explicitly listed services
      (lib.listToAttrs (map (name: mkServiceOverride name hardeningProfile) cfg.hardenedServices))
    ];

    # Global systemd settings via settings.Manager
    systemd.settings.Manager = {
      DefaultLimitCORE = "0";
      DefaultLimitNOFILE = "1024:524288";
      DefaultLimitNPROC = "512:512";
    };

    # Apply hardening to user services
    systemd.user.services = lib.mkIf cfg.user.enable (
      lib.listToAttrs (
        map (
          name:
          lib.nameValuePair name {
            serviceConfig = lib.mkDefault userHardening;
          }
        ) cfg.user.hardenedServices
      )
    );

    # Environment hardening
    environment.sessionVariables = {
      # Prevent core dumps
      RLIMIT_CORE = "0";
    };

    # PAM configuration for systemd-user
    security.pam.services.systemd-user = lib.mkIf cfg.user.enable {
      # Ensure user services inherit security settings
      setEnvironment = true;
    };

    # Warnings about strict profile
    warnings = lib.optional (cfg.profile == "strict" && cfg.hardenedServices != [ ]) ''
      vitrify.systemdHardening: Strict profile is enabled. Services like docker,
      libvirtd, and display managers may require exemptions or custom overrides.
    '';
  };
}
