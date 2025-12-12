# MODULE: Userspace Memory Allocator
{
  config,
  lib,
  ...
}:
let
  cfg = config.vitrify.userspace.memoryAllocator;
in
{
  options.vitrify.userspace.memoryAllocator = {
    provider = lib.mkOption {
      type = lib.types.str;
      default = "graphene-hardened";
      description = ''
        Memory allocator provider to use system-wide.
        This maps to environment.memoryAllocator.provider.
      '';
      example = "scudo";
    };
  };

  config = {
    environment.memoryAllocator.provider = lib.mkDefault cfg.provider;
  };
}
