# MODULE: Userspace Kernel Module Blacklist
{
  config,
  lib,
  ...
}:
let
  cfg = config.vitrify.userspace.blacklistedKernelModules;

  baseBlacklist = [
    # Uncommon filesystems (attack surface)
    "adfs"
    "affs"
    "befs"
    "bfs"
    "cramfs"
    "efs"
    "erofs"
    "exofs"
    "f2fs"
    "freevxfs"
    "hfs"
    "hpfs"
    "jfs"
    "minix"
    "nilfs2"
    "ntfs"
    "omfs"
    "qnx4"
    "qnx6"
    "sysv"
    "udf"
    "ufs"

    # Amateur radio protocols
    "ax25"
    "netrom"
    "rose"

    # Dangerous hardware interfaces
    "firewire-core"
    "firewire_ohci"
    "firewire_sbp2"
    "thunderbolt"

    # Virtual video test driver (attack surface)
    "vivid"
  ];

  effectiveBlacklist = lib.subtractLists cfg.remove (lib.unique (baseBlacklist ++ cfg.extra));
in
{
  options.vitrify.userspace.blacklistedKernelModules = {
    extra = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Additional kernel modules to blacklist beyond the Vitrify baseline.
      '';
      example = [
        "bluetooth"
        "usb_storage"
      ];
    };

    remove = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Kernel modules to remove from the Vitrify baseline blacklist.
      '';
      example = [
        "erofs"
        "f2fs"
      ];
    };
  };

  config = {
    boot.blacklistedKernelModules = lib.mkDefault effectiveBlacklist;
  };
}
