{
  description = "Vitrify - Security Hardening Modules for NixOS";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      flake-parts,
      ...
    }:
    let
      modules = import ./modules;
    in
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];

      flake.nixosModules = {
        hardenedKernel = modules.hardenedKernel;
        hardenedUserspace = modules.hardenedUserspace;
        paranoia = modules.paranoia;
        verity = modules.verity;
        fsverity = modules.fsverity;
        systemdHardening = modules.systemdHardening;
        all = modules.all;

        # Convenience alias
        default = modules.all;
      };

      perSystem =
        { system, pkgs, ... }:
        let
          tests = import ./tests { inherit pkgs self; };
        in
        {
          # VM tests and build checks
          # Run with: nix flake check
          checks = {
            inherit (tests)
              userspace
              paranoiaBalanced
              paranoiaStrict
              paranoiaParanoid
              fullConfig
              verity
              fsverity
              systemdHardening
              ;

            # Verify the kernel module configuration evaluates correctly
            # This doesn't build the kernel, just checks the NixOS config
            kernelConfigEval =
              let
                eval = nixpkgs.lib.nixosSystem {
                  inherit system;
                  modules = [
                    self.nixosModules.hardenedKernel
                    {
                      # Minimal config to make evaluation succeed
                      fileSystems."/" = {
                        device = "/dev/disk/by-label/nixos";
                        fsType = "ext4";
                      };
                      boot.loader.grub.device = "/dev/sda";
                    }
                  ];
                };
              in
              pkgs.runCommand "kernel-config-eval" { } ''
                echo "Kernel module configuration evaluated successfully"
                echo "Kernel package: ${eval.config.boot.kernelPackages.kernel.name}"
                mkdir -p $out
                echo "success" > $out/result
              '';

            # Verify userspace module configuration evaluates correctly
            userspaceConfigEval =
              let
                eval = nixpkgs.lib.nixosSystem {
                  inherit system;
                  modules = [
                    self.nixosModules.hardenedUserspace
                    {
                      fileSystems."/" = {
                        device = "/dev/disk/by-label/nixos";
                        fsType = "ext4";
                      };
                      boot.loader.grub.device = "/dev/sda";
                    }
                  ];
                };
              in
              pkgs.runCommand "userspace-config-eval" { } ''
                echo "Userspace module configuration evaluated successfully"
                echo "Memory allocator: ${eval.config.environment.memoryAllocator.provider}"
                mkdir -p $out
                echo "success" > $out/result
              '';

            # Verify paranoia defaults evaluate for each level
            paranoiaBalancedConfigEval =
              let
                eval = nixpkgs.lib.nixosSystem {
                  inherit system;
                  modules = [
                    self.nixosModules.hardenedUserspace
                    self.nixosModules.paranoia
                    {
                      vitrify.paranoia.level = "balanced";
                      fileSystems."/" = {
                        device = "/dev/disk/by-label/nixos";
                        fsType = "ext4";
                      };
                      boot.loader.grub.device = "/dev/sda";
                    }
                  ];
                };
              in
              pkgs.runCommand "paranoia-balanced-config-eval" { } ''
                echo "Paranoia balanced configuration evaluated successfully"
                echo "Memory allocator: ${eval.config.environment.memoryAllocator.provider}"
                mkdir -p $out
                echo "success" > $out/result
              '';

            paranoiaStrictConfigEval =
              let
                eval = nixpkgs.lib.nixosSystem {
                  inherit system;
                  modules = [
                    self.nixosModules.hardenedUserspace
                    self.nixosModules.paranoia
                    {
                      vitrify.paranoia.level = "strict";
                      fileSystems."/" = {
                        device = "/dev/disk/by-label/nixos";
                        fsType = "ext4";
                      };
                      boot.loader.grub.device = "/dev/sda";
                    }
                  ];
                };
              in
              pkgs.runCommand "paranoia-strict-config-eval" { } ''
                echo "Paranoia strict configuration evaluated successfully"
                echo "Memory allocator: ${eval.config.environment.memoryAllocator.provider}"
                mkdir -p $out
                echo "success" > $out/result
              '';

            paranoiaParanoidConfigEval =
              let
                eval = nixpkgs.lib.nixosSystem {
                  inherit system;
                  modules = [
                    self.nixosModules.hardenedUserspace
                    self.nixosModules.paranoia
                    {
                      vitrify.paranoia.level = "paranoid";
                      fileSystems."/" = {
                        device = "/dev/disk/by-label/nixos";
                        fsType = "ext4";
                      };
                      boot.loader.grub.device = "/dev/sda";
                    }
                  ];
                };
              in
              pkgs.runCommand "paranoia-paranoid-config-eval" { } ''
                echo "Paranoia paranoid configuration evaluated successfully"
                echo "Memory allocator: ${eval.config.environment.memoryAllocator.provider}"
                mkdir -p $out
                echo "success" > $out/result
              '';

            # Verify paranoia defaults can be overridden cleanly
            paranoiaOverrideConfigEval =
              let
                eval = nixpkgs.lib.nixosSystem {
                  inherit system;
                  modules = [
                    self.nixosModules.hardenedUserspace
                    self.nixosModules.paranoia
                    {
                      vitrify.paranoia.level = "paranoid";
                      vitrify.userspace.memoryAllocator.provider = "libc";
                      fileSystems."/" = {
                        device = "/dev/disk/by-label/nixos";
                        fsType = "ext4";
                      };
                      boot.loader.grub.device = "/dev/sda";
                    }
                  ];
                };
              in
              pkgs.runCommand "paranoia-override-config-eval" { } ''
                echo "Paranoia override configuration evaluated successfully"
                echo "Memory allocator: ${eval.config.environment.memoryAllocator.provider}"
                mkdir -p $out
                echo "success" > $out/result
              '';

            # Verify combined configuration evaluates correctly
            allConfigEval =
              let
                eval = nixpkgs.lib.nixosSystem {
                  inherit system;
                  modules = [
                    self.nixosModules.all
                    {
                      fileSystems."/" = {
                        device = "/dev/disk/by-label/nixos";
                        fsType = "ext4";
                      };
                      boot.loader.grub.device = "/dev/sda";
                    }
                  ];
                };
              in
              pkgs.runCommand "all-config-eval" { } ''
                echo "Combined module configuration evaluated successfully"
                echo "Kernel: ${eval.config.boot.kernelPackages.kernel.name}"
                echo "Memory allocator: ${eval.config.environment.memoryAllocator.provider}"
                mkdir -p $out
                echo "success" > $out/result
              '';

            # Verify verity module with sample configuration
            verityConfigEval =
              let
                eval = nixpkgs.lib.nixosSystem {
                  inherit system;
                  modules = [
                    self.nixosModules.verity
                    {
                      fileSystems."/" = {
                        device = "/dev/disk/by-label/nixos";
                        fsType = "ext4";
                      };
                      boot.loader.grub.device = "/dev/sda";

                      # Enable verity with a sample configuration
                      vitrify.verity = {
                        enable = true;
                        trustedKeys = [ ];
                        devices.testdata = {
                          dataDevice = "/dev/disk/by-partlabel/data";
                          hashDevice = "/dev/disk/by-partlabel/hash";
                          rootHash = "0000000000000000000000000000000000000000000000000000000000000000";
                          signatureVerification = false;
                          mountPoint = "/mnt/verified";
                        };
                      };
                    }
                  ];
                };
              in
              pkgs.runCommand "verity-config-eval" { } ''
                echo "Verity module configuration evaluated successfully"
                echo "Verity enabled: ${nixpkgs.lib.boolToString eval.config.vitrify.verity.enable}"
                mkdir -p $out
                echo "success" > $out/result
              '';

            # Verify fsverity module with sample configuration
            fsverityConfigEval =
              let
                eval = nixpkgs.lib.nixosSystem {
                  inherit system;
                  modules = [
                    self.nixosModules.fsverity
                    {
                      fileSystems."/" = {
                        device = "/dev/disk/by-label/nixos";
                        fsType = "ext4";
                      };
                      boot.loader.grub.device = "/dev/sda";

                      # Enable fsverity with sample configuration
                      vitrify.fsverity = {
                        enable = true;
                        protectedPaths = [
                          "/etc/ssh/sshd_config"
                          "/etc/sudoers"
                        ];
                        nixStore = {
                          enable = false;
                          autoDetect = true;
                        };
                      };
                    }
                  ];
                };
              in
              pkgs.runCommand "fsverity-config-eval" { } ''
                echo "fs-verity module configuration evaluated successfully"
                echo "fs-verity enabled: ${nixpkgs.lib.boolToString eval.config.vitrify.fsverity.enable}"
                mkdir -p $out
                echo "success" > $out/result
              '';

            # Verify systemd hardening module with sample configuration
            systemdHardeningConfigEval =
              let
                eval = nixpkgs.lib.nixosSystem {
                  inherit system;
                  modules = [
                    self.nixosModules.systemdHardening
                    {
                      fileSystems."/" = {
                        device = "/dev/disk/by-label/nixos";
                        fsType = "ext4";
                      };
                      boot.loader.grub.device = "/dev/sda";

                      # Enable systemd hardening with sample configuration
                      vitrify.systemdHardening = {
                        enable = true;
                        profile = "base";
                        exemptServices = [ "docker" ];
                        networkServices = [
                          "nginx"
                          "sshd"
                        ];
                        user.enable = true;
                      };
                    }
                  ];
                };
              in
              pkgs.runCommand "systemd-hardening-config-eval" { } ''
                echo "systemd hardening module configuration evaluated successfully"
                echo "systemd hardening enabled: ${nixpkgs.lib.boolToString eval.config.vitrify.systemdHardening.enable}"
                echo "profile: ${eval.config.vitrify.systemdHardening.profile}"
                mkdir -p $out
                echo "success" > $out/result
              '';
          };

          packages =
            let
              isoStrict = nixpkgs.lib.nixosSystem {
                inherit system;
                modules = [
                  self.nixosModules.all
                  ./iso/strict.nix
                ];
              };
            in
            {
              isoStrict = isoStrict.config.system.build.isoImage;
            };

          # Development shell with useful tools
          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              just
              nixfmt-rfc-style
              nil
            ];
          };
        };
    };
}
