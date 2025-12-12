# MODULE: Userspace Kernel Lockdown Controls
{
  config,
  lib,
  ...
}:
let
  cfg = config.vitrify.userspace.kernelLockdown;
in
{
  options.vitrify.userspace.kernelLockdown = {
    lockKernelModules = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Lock kernel modules after boot to prevent runtime loading.";
    };

    protectKernelImage = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Protect the kernel image from modification.";
    };
  };

  config = {
    security.lockKernelModules = lib.mkDefault cfg.lockKernelModules;
    security.protectKernelImage = lib.mkDefault cfg.protectKernelImage;
  };
}
