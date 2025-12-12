# MODULE: Userspace Permission Defaults
{
  config,
  lib,
  ...
}:
let
  cfg = config.vitrify.userspace;
  shellUmask = "umask ${cfg.umask.shell}";
in
{
  options.vitrify.userspace = {
    umask = {
      pam = lib.mkOption {
        type = lib.types.str;
        default = "0077";
        description = "Default umask for PAM-created home directories.";
      };

      loginDefs = lib.mkOption {
        type = lib.types.str;
        default = "077";
        description = "Default UMASK value in /etc/login.defs.";
      };

      systemdUser = lib.mkOption {
        type = lib.types.str;
        default = "0077";
        description = "Default UMask for systemd user services.";
      };

      shell = lib.mkOption {
        type = lib.types.str;
        default = "0077";
        description = "Default umask applied to interactive login shells.";
      };
    };

    sudo.execWheelOnly = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Restrict sudo execution to members of the wheel group.";
    };
  };

  config = {
    security.pam.makeHomeDir.umask = lib.mkDefault cfg.umask.pam;
    security.loginDefs.settings.UMASK = lib.mkDefault cfg.umask.loginDefs;
    systemd.services."user@".serviceConfig.UMask = lib.mkDefault cfg.umask.systemdUser;
    environment.loginShellInit = lib.mkDefault shellUmask;

    security.sudo.execWheelOnly = lib.mkDefault cfg.sudo.execWheelOnly;
  };
}
