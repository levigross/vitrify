# MODULE: Userspace Mount Hardening
{
  config,
  lib,
  ...
}:
let
  cfg = config.vitrify.userspace.mountHardening;

  tmpEnabled = cfg.tmpNosuid || cfg.tmpNoexec || cfg.nodevOnNonDeviceMounts;
  varTmpEnabled = cfg.varTmpNosuid || cfg.varTmpNoexec || cfg.nodevOnNonDeviceMounts;

  tmpOptions = [
    "bind"
  ]
  ++ lib.optional cfg.tmpNosuid "nosuid"
  ++ lib.optional cfg.tmpNoexec "noexec"
  ++ lib.optional cfg.nodevOnNonDeviceMounts "nodev";

  varTmpOptions = [
    "bind"
  ]
  ++ lib.optional cfg.varTmpNosuid "nosuid"
  ++ lib.optional cfg.varTmpNoexec "noexec"
  ++ lib.optional cfg.nodevOnNonDeviceMounts "nodev";

  mkBindMount = mountPoint: options: {
    what = mountPoint;
    where = mountPoint;
    type = "none";
    mountConfig.Options = lib.concatStringsSep "," options;
  };

  bindMounts = lib.concatLists [
    (lib.optional tmpEnabled (mkBindMount "/tmp" tmpOptions))
    (lib.optional varTmpEnabled (mkBindMount "/var/tmp" varTmpOptions))
  ];
in
{
  options.vitrify.userspace.mountHardening = {
    tmpNosuid = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Mount /tmp with nosuid.";
    };

    tmpNoexec = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Mount /tmp with noexec.";
    };

    varTmpNosuid = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Mount /var/tmp with nosuid.";
    };

    varTmpNoexec = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Mount /var/tmp with noexec.";
    };

    nodevOnNonDeviceMounts = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Add nodev to Vitrify-managed bind mounts (such as /tmp and /var/tmp).
      '';
    };
  };

  config = lib.mkIf (tmpEnabled || varTmpEnabled) {
    systemd.mounts = bindMounts;
  };
}
