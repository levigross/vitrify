# MODULE: Userspace Systemd Defaults
{
  config,
  lib,
  ...
}:
let
  cfg = config.vitrify.userspace.systemdDefaults;

  managerDefaults = lib.mapAttrs (_: value: lib.mkOverride 900 value) cfg.manager;
in
{
  options.vitrify.userspace.systemdDefaults = {
    manager = lib.mkOption {
      type = lib.types.attrsOf (lib.types.oneOf [
        lib.types.bool
        lib.types.int
        lib.types.str
        lib.types.path
      ]);
      default = {
        DefaultLimitCORE = "0";
        DefaultOOMScoreAdjust = 0;
        CrashShell = false;
        ProtectSystem = "auto";
        DefaultCPUAccounting = true;
        DefaultMemoryAccounting = true;
        DefaultIOAccounting = true;
      };
      description = "Default systemd Manager settings applied system-wide.";
    };
  };

  config = {
    systemd.settings.Manager = managerDefaults;
  };
}
