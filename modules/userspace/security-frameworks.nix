# MODULE: Userspace Security Frameworks
{
  config,
  lib,
  ...
}:
let
  cfg = config.vitrify.userspace.securityFrameworks;
in
{
  options.vitrify.userspace.securityFrameworks = {
    apparmor = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable AppArmor mandatory access control.";
    };

    audit = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable kernel audit support.";
    };

    auditd = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable the auditd daemon.";
    };
  };

  config = {
    security.apparmor.enable = lib.mkDefault cfg.apparmor;
    security.audit.enable = lib.mkDefault cfg.audit;
    security.auditd.enable = lib.mkDefault cfg.auditd;
  };
}
