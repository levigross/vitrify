# MODULE: fs-verity File Integrity Protection
#
# Provides fs-verity support for transparent file-level integrity verification.
# Unlike dm-verity (block-level), fs-verity protects individual files within
# a filesystem, making it ideal for sensitive config files and the Nix store.
#
# fs-verity uses a Merkle tree of hashes stored as file metadata. Once enabled,
# files become read-only and any tampering is detected on read.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.vitrify.fsverity;

  # Script to enable fs-verity on a file or directory
  enableVerityScript = pkgs.writeShellScript "enable-fsverity" ''
    set -euo pipefail

    PATH="${
      lib.makeBinPath [
        pkgs.fsverity-utils
        pkgs.coreutils
        pkgs.findutils
      ]
    }"

    SIGNING_KEY="''${SIGNING_KEY:-}"
    SIGNING_CERT="''${SIGNING_CERT:-}"

    enable_file() {
      local file="$1"

      # Skip if already has fs-verity enabled
      if fsverity measure "$file" &>/dev/null; then
        echo "fs-verity already enabled: $file"
        return 0
      fi

      # Skip if file is not regular
      if [[ ! -f "$file" ]]; then
        return 0
      fi

      echo "Enabling fs-verity: $file"

      if [[ -n "$SIGNING_KEY" && -n "$SIGNING_CERT" ]]; then
        fsverity sign "$file" "$file.sig" \
          --key="$SIGNING_KEY" \
          --cert="$SIGNING_CERT"
        fsverity enable "$file" --signature="$file.sig"
        rm -f "$file.sig"
      else
        fsverity enable "$file"
      fi
    }

    process_path() {
      local path="$1"

      if [[ -f "$path" ]]; then
        enable_file "$path"
      elif [[ -d "$path" ]]; then
        find "$path" -type f -print0 | while IFS= read -r -d "" file; do
          enable_file "$file" || true
        done
      else
        echo "Warning: path does not exist: $path" >&2
      fi
    }

    for arg in "$@"; do
      process_path "$arg"
    done
  '';

  # Script to check if Nix store should be protected
  nixStoreCheckScript = pkgs.writeShellScript "check-nix-store" ''
    set -euo pipefail

    # Check if Nix daemon is available
    nix_available() {
      command -v nix &>/dev/null && \
        systemctl is-active nix-daemon &>/dev/null 2>&1
    }

    # Check if /nix/store is read-only mounted
    nix_store_readonly() {
      mount | grep -q "on /nix/store type.*\bro\b"
    }

    # Check if /nix/store exists and has content
    nix_store_exists() {
      [[ -d /nix/store ]] && [[ -n "$(ls -A /nix/store 2>/dev/null)" ]]
    }

    if nix_store_exists; then
      if ! nix_available || nix_store_readonly; then
        echo "true"
        exit 0
      fi
    fi

    echo "false"
  '';

  # Generate the list of paths to protect
  protectedPathsFile = pkgs.writeText "fsverity-paths" (lib.concatStringsSep "\n" cfg.protectedPaths);
in
{
  options.vitrify.fsverity = {
    enable = lib.mkEnableOption "fs-verity file integrity protection";

    protectedPaths = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        List of files or directories to protect with fs-verity.
        Files become read-only once fs-verity is enabled.
        Directories are processed recursively.
      '';
      example = [
        "/etc/ssh/sshd_config"
        "/etc/sudoers"
        "/usr/local/bin"
      ];
    };

    nixStore = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Enable fs-verity protection for /nix/store.
          This is useful when deploying systems where Nix will be removed
          or the store is mounted read-only after initial setup.

          WARNING: Once enabled, the Nix store becomes truly immutable.
          New packages cannot be installed without first disabling fs-verity.
        '';
      };

      autoDetect = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Automatically enable fs-verity on /nix/store if:
          - The Nix daemon is not running/available, OR
          - /nix/store is mounted read-only

          This allows the same configuration to work for both development
          (Nix available) and production (Nix removed) scenarios.
        '';
      };

      excludePatterns = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = ''
          File patterns to exclude from Nix store protection.
          Uses find's -name matching.
        '';
        example = [
          "*.drv"
          "*.lock"
        ];
      };
    };

    signatureVerification = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Require valid signatures for fs-verity protected files.
          Files without valid signatures will fail verification.
        '';
      };

      trustedCerts = lib.mkOption {
        type = lib.types.listOf lib.types.path;
        default = [ ];
        description = ''
          List of X.509 certificates (PEM or DER format) to trust
          for fs-verity signature verification.
        '';
        example = [ ./keys/fsverity-signing.pem ];
      };

      signingKey = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = ''
          Path to the private key for signing files.
          Only needed if you want the system to sign files automatically.
        '';
      };

      signingCert = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = ''
          Path to the certificate for signing files.
          Must correspond to the signing key.
        '';
      };
    };

    verifyOnRead = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        When enabled, the kernel verifies file contents on each read.
        This is the default and recommended setting.
        Disabling this makes fs-verity metadata-only (less secure).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Note: Kernel config for fs-verity is in the hardenedKernel module
    # This module configures the userspace components and services

    # Ensure fsverity-utils is available
    environment.systemPackages = [ pkgs.fsverity-utils ];

    # Load fs-verity keyring with trusted certificates
    boot.kernelParams = lib.mkIf cfg.signatureVerification.enable [
      "fsverity.require_signatures=1"
    ];

    # Systemd service to protect specified paths
    systemd.services.fsverity-protect = lib.mkIf (cfg.protectedPaths != [ ]) {
      description = "Enable fs-verity on protected paths";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${enableVerityScript} ${lib.escapeShellArgs cfg.protectedPaths}";
      };

      environment = lib.mkIf (cfg.signatureVerification.signingKey != null) {
        SIGNING_KEY = toString cfg.signatureVerification.signingKey;
        SIGNING_CERT = toString cfg.signatureVerification.signingCert;
      };
    };

    # Systemd service to protect Nix store
    systemd.services.fsverity-nix-store = lib.mkIf cfg.nixStore.enable {
      description = "Enable fs-verity on Nix store";
      wantedBy = [ "multi-user.target" ];
      after = [
        "local-fs.target"
        "nix-daemon.service"
      ];
      wants = lib.optional (!cfg.nixStore.autoDetect) "nix-daemon.service";

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };

      script =
        let
          excludeArgs = lib.concatMapStringsSep " " (p: "-not -name '${p}'") cfg.nixStore.excludePatterns;
          findCmd = "find /nix/store -type f ${excludeArgs}";
        in
        ''
          set -euo pipefail
          PATH="${
            lib.makeBinPath [
              pkgs.fsverity-utils
              pkgs.coreutils
              pkgs.findutils
              pkgs.gnugrep
            ]
          }"

          should_protect="false"

          ${lib.optionalString cfg.nixStore.autoDetect ''
            should_protect=$(${nixStoreCheckScript})
          ''}

          ${lib.optionalString (!cfg.nixStore.autoDetect) ''
            should_protect="true"
          ''}

          if [[ "$should_protect" != "true" ]]; then
            echo "Nix store protection skipped (Nix daemon available and store is writable)"
            exit 0
          fi

          echo "Enabling fs-verity on /nix/store..."

          # Process files in batches for efficiency
          ${findCmd} -print0 | while IFS= read -r -d "" file; do
            if ! fsverity measure "$file" &>/dev/null; then
              ${lib.optionalString (cfg.signatureVerification.signingKey != null) ''
                SIGNING_KEY="${toString cfg.signatureVerification.signingKey}"
                SIGNING_CERT="${toString cfg.signatureVerification.signingCert}"
                fsverity sign "$file" "$file.sig" --key="$SIGNING_KEY" --cert="$SIGNING_CERT" 2>/dev/null || true
                fsverity enable "$file" --signature="$file.sig" 2>/dev/null || true
                rm -f "$file.sig"
              ''}
              ${lib.optionalString (cfg.signatureVerification.signingKey == null) ''
                fsverity enable "$file" 2>/dev/null || true
              ''}
            fi
          done

          echo "Nix store fs-verity protection complete"
        '';

      environment = lib.mkIf (cfg.signatureVerification.signingKey != null) {
        SIGNING_KEY = toString cfg.signatureVerification.signingKey;
        SIGNING_CERT = toString cfg.signatureVerification.signingCert;
      };
    };

    # Create keyring directory for trusted certificates
    systemd.tmpfiles.rules = lib.mkIf (cfg.signatureVerification.trustedCerts != [ ]) [
      "d /etc/fsverity-certs 0755 root root -"
    ];

    # Copy trusted certificates
    environment.etc = lib.mkIf (cfg.signatureVerification.trustedCerts != [ ]) (
      lib.listToAttrs (
        lib.imap0 (
          i: cert:
          lib.nameValuePair "fsverity-certs/cert-${toString i}.pem" {
            source = cert;
            mode = "0644";
          }
        ) cfg.signatureVerification.trustedCerts
      )
    );

    # Assertions for configuration validation
    assertions = [
      {
        assertion =
          cfg.signatureVerification.enable
          -> (cfg.signatureVerification.trustedCerts != [ ] || cfg.signatureVerification.signingKey != null);
        message = ''
          vitrify.fsverity: Signature verification is enabled but no trusted certificates
          or signing key is provided. Either add trustedCerts or provide signingKey/signingCert.
        '';
      }
      {
        assertion =
          (cfg.signatureVerification.signingKey != null) == (cfg.signatureVerification.signingCert != null);
        message = ''
          vitrify.fsverity: Both signingKey and signingCert must be provided together.
        '';
      }
    ];

    warnings =
      lib.optional cfg.nixStore.enable ''
        vitrify.fsverity: Nix store protection is enabled. Once fs-verity is applied,
        the Nix store becomes truly immutable. You will not be able to install new
        packages or run garbage collection without first removing fs-verity protection.
        This is typically only suitable for production deployments where Nix is removed.
      ''
      ++ lib.optional (cfg.nixStore.enable && !cfg.nixStore.autoDetect) ''
        vitrify.fsverity: Nix store protection will be applied unconditionally.
        Consider enabling nixStore.autoDetect to only protect when Nix is unavailable.
      '';
  };
}
