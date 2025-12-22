# MODULE: Userspace Nix Daemon Hardening
{
  config,
  lib,
  ...
}:
let
  cfg = config.vitrify.userspace.nix;
in
{
  options.vitrify.userspace.nix = {
    allowedUsers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "@wheel" ];
      description = "Users or groups allowed to use the Nix daemon.";
    };

    trustedUsers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "@wheel" ];
      description = "Users or groups treated as trusted by the Nix daemon.";
    };

    sandbox = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable Nix build sandboxing.";
    };

    sandboxFallback = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Allow unsandboxed builds if sandboxing is unavailable.
        Keeping this disabled fails closed when sandboxing is broken.
      '';
    };
  };

  config = {
    nix.settings = {
      "allowed-users" = lib.mkDefault cfg.allowedUsers;
      "trusted-users" = lib.mkDefault cfg.trustedUsers;
      sandbox = lib.mkDefault cfg.sandbox;
      "sandbox-fallback" = lib.mkDefault cfg.sandboxFallback;
    };
  };
}
