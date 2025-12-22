# MODULE: Userspace Namespace Controls
{
  config,
  lib,
  ...
}:
let
  cfg = config.vitrify.userspace.userNamespaces;
in
{
  options.vitrify.userspace.userNamespaces = {
    unprivilegedUsernsClone = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether to allow unprivileged user namespace creation.
        Disabling this reduces attack surface but breaks some sandboxed apps.
      '';
    };
  };

  config = {
    security.unprivilegedUsernsClone = lib.mkDefault cfg.unprivilegedUsernsClone;
  };
}
