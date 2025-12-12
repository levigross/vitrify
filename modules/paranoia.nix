# MODULE: Paranoia Level Defaults
{
  config,
  lib,
  options,
  ...
}:
let
  cfg = config.vitrify.paranoia;

  strictBlacklistExtra = [
    "bluetooth"
    "btusb"
    "usb_storage"
    "uas"
  ];

  paranoidBlacklistExtra = strictBlacklistExtra ++ [
    "btrtl"
    "btintel"
    "btbcm"
    "btmtk"
    "bnep"
    "rfcomm"
    "hidp"
    "uvcvideo"
  ];

  levelDefaults = {
    balanced = {
      memoryAllocator = "scudo";
      sysctlDefaults = {
        "kernel.perf_event_paranoid" = 2;
      };
      blacklistExtra = [ ];
      unprivilegedUsernsClone = true;
      systemdProfile = "base";
      mountHardening = {
        tmpNosuid = true;
      };
      nixSandboxFallback = true;
    };

    strict = {
      memoryAllocator = "graphene-hardened-light";
      sysctlDefaults = {
        "kernel.yama.ptrace_scope" = 3;
        "kernel.perf_event_paranoid" = 3;
        "vm.mmap_rnd_bits" = 32;
        "vm.mmap_rnd_compat_bits" = 16;
      };
      blacklistExtra = strictBlacklistExtra;
      unprivilegedUsernsClone = false;
      systemdProfile = "moderate";
      mountHardening = {
        tmpNosuid = true;
        tmpNoexec = true;
        varTmpNosuid = true;
        varTmpNoexec = true;
      };
      nixSandboxFallback = true;
    };

    paranoid = {
      memoryAllocator = "graphene-hardened";
      sysctlDefaults = {
        "kernel.yama.ptrace_scope" = 3;
        "kernel.perf_event_paranoid" = 3;
        "vm.mmap_rnd_bits" = 32;
        "vm.mmap_rnd_compat_bits" = 16;
      };
      blacklistExtra = paranoidBlacklistExtra;
      unprivilegedUsernsClone = false;
      systemdProfile = "strict";
      mountHardening = {
        tmpNosuid = true;
        tmpNoexec = true;
        varTmpNosuid = true;
        varTmpNoexec = true;
        nodevOnNonDeviceMounts = true;
      };
      nixSandboxFallback = false;
    };
  };

  defaults = levelDefaults.${cfg.level};

  sysctlDefaults = defaults.sysctlDefaults;
  mountHardeningDefaults = lib.mapAttrs (_: value: lib.mkDefault value) defaults.mountHardening;

  hasUserspace = lib.hasAttrByPath [ "vitrify" "userspace" ] options;
  hasSystemd = lib.hasAttrByPath [ "vitrify" "systemdHardening" ] options;
in
{
  options.vitrify.paranoia = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Enable the paranoia defaults layer. When disabled, only the underlying
        module defaults apply and no paranoia-level overrides are set.
      '';
    };

    level = lib.mkOption {
      type = lib.types.enum [
        "balanced"
        "strict"
        "paranoid"
      ];
      default = "balanced";
      description = ''
        Paranoia level used to select hardened defaults. All defaults are
        applied with mkDefault so explicit overrides always win.
      '';
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    (lib.optionalAttrs hasUserspace {
      vitrify.userspace.memoryAllocator.provider = lib.mkDefault defaults.memoryAllocator;
      vitrify.userspace.sysctl.defaults = sysctlDefaults;
      vitrify.userspace.blacklistedKernelModules.extra = lib.mkDefault defaults.blacklistExtra;
      vitrify.userspace.userNamespaces.unprivilegedUsernsClone = lib.mkDefault defaults.unprivilegedUsernsClone;
      vitrify.userspace.mountHardening = mountHardeningDefaults;
      vitrify.userspace.nix.sandboxFallback = lib.mkDefault defaults.nixSandboxFallback;
    })
    (lib.optionalAttrs hasSystemd {
      vitrify.systemdHardening.profile = lib.mkDefault defaults.systemdProfile;
    })
  ]);
}
