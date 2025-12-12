{ modulesPath, ... }:
{
  imports = [
    (modulesPath + "/installer/cd-dvd/installation-cd-minimal.nix")
  ];

  system.stateVersion = "25.11";

  vitrify.paranoia.level = "paranoid";
  vitrify.systemdHardening.enable = true;
  vitrify.systemdHardening.profile = "strict";

  isoImage = {
    isoName = "vitrify-paranoid.iso";
    volumeID = "VITRIFY_PARANOID";
  };
}
