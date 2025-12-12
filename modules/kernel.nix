# MODULE: Hardened Kernel (Clang + kCFI + LTO)
#
# Provides a custom Linux kernel compiled with Clang/LLVM toolchain,
# enabling kCFI (Kernel Control Flow Integrity) and Thin LTO for
# enhanced security against control-flow hijacking attacks.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.vitrify.kernel.kernelParams;

  baseKernelParams = [
    "slab_nomerge"
    "init_on_alloc=1"
    "init_on_free=1"
    "page_alloc.shuffle=1"
    "lockdown=confidentiality"
    "debugfs=off"
    "module.sig_enforce=1"
    "lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
  ];

  effectiveKernelParams = lib.subtractLists cfg.remove (baseKernelParams ++ cfg.extra);
in
{
  options.vitrify.kernel.kernelParams = {
    extra = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Additional kernel parameters to append to Vitrify defaults.";
      example = [ "pti=on" ];
    };

    remove = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Kernel parameters to remove from Vitrify defaults.";
      example = [ "debugfs=off" ];
    };
  };

  config = {
    nixpkgs.overlays = [
      (final: prev: {
        linux_kcfi =
          let
            llvmPackages = final.llvmPackages_latest;
          in
          prev.linuxPackages_6_12.kernel.override {
            stdenv = llvmPackages.stdenv;

            argsOverride = {
              nativeBuildInputs = (prev.linuxPackages_6_12.kernel.nativeBuildInputs or [ ]) ++ [
                llvmPackages.lld
                llvmPackages.llvm
                pkgs.openssl
              ];

              makeFlags = [
                "LLVM=1"
                "LLVM_IAS=1"
                "CC=clang"
                "LD=ld.lld"
                "HOSTCC=clang"
                "HOSTLD=ld.lld"
                "KCFLAGS=-fsanitize=kcfi"
              ];
            };

            structuredExtraConfig = with lib.kernel; {
              # Stack protection
              STACKPROTECTOR = yes;
              STACKPROTECTOR_STRONG = yes;

              # Address space randomization
              RANDOMIZE_BASE = yes;
              RANDOMIZE_MEMORY = yes;

              # Memory protection
              STRICT_KERNEL_RWX = yes;
              STRICT_MODULE_RWX = yes;

              # Link-time optimization with CFI
              LTO_CLANG_THIN = option yes;
              CFI_CLANG = yes;
              CFI_PERMISSIVE = no;

              # Zero-initialize stack variables
              INIT_STACK_ALL_ZERO = yes;

              # Hardened memory copy operations
              HARDENED_USERCOPY = yes;
              SECURITY_SAFESETID = yes;

              # Slab allocator hardening
              INIT_ON_ALLOC_DEFAULT_ON = yes;
              INIT_ON_FREE_DEFAULT_ON = yes;
              SLAB_MERGE_DEFAULT = no;
              SLAB_FREELIST_RANDOM = yes;
              SLAB_FREELIST_HARDENED = yes;
              SHUFFLE_PAGE_ALLOCATOR = yes;
              VMAP_STACK = yes;

              # BPF hardening
              BPF_JIT_ALWAYS_ON = lib.mkForce yes;

              # Hide kernel symbols from unprivileged users
              KALLSYMS_ALL = no;

              # Security modules
              SECURITY_APPARMOR = yes;
              SECURITY_LOCKDOWN_LSM = lib.mkForce yes;

              # /dev/mem restrictions
              DEVMEM = yes;
              STRICT_DEVMEM = yes;
              IO_STRICT_DEVMEM = yes;
              DEVPORT = no;

              # Disable dangerous features
              KEXEC = no;
              CRASH_DUMP = lib.mkForce (option no);
              PROC_VMCORE = lib.mkForce (option no);
              KEXEC_FILE = lib.mkForce (option no);
              KEXEC_JUMP = lib.mkForce (option no);
              HIBERNATION = lib.mkForce (option no);

              # Legacy syscall restrictions
              LEGACY_VSYSCALL_NONE = yes;
              MODIFY_LDT_SYSCALL = no;

              # Undefined behavior sanitizer
              UBSAN = yes;
              UBSAN_TRAP = yes;
              UBSAN_BOUNDS = yes;
              UBSAN_LOCAL_BOUNDS = option yes;

              # Disable kernel debugger
              KGDB = no;

              # Restrict dmesg access
              SECURITY_DMESG_RESTRICT = yes;

              # Panic behavior
              PANIC_ON_OOPS = yes;
              PANIC_TIMEOUT = freeform "-1";
              BUG_ON_DATA_CORRUPTION = yes;

              # Module signing
              EXPERT = yes;
              CRYPTO = yes;
              CRYPTO_SHA256 = lib.mkForce yes;
              CRYPTO_SHA512 = yes;
              MODULES = yes;
              MODULE_SIG = lib.mkForce yes;
              MODULE_SIG_FORCE = yes;
              MODULE_SIG_SHA512 = yes;
              SYSTEM_TRUSTED_KEYRING = yes;

              # Restrict user namespaces
              USER_NS = lib.mkDefault no;

              # dm-verity verified boot support
              # Keep device-mapper as a module to avoid Kconfig loops when DAX is set to m.
              # The initrd will load dm_mod/dm_verity as needed.
              BLK_DEV_DM = lib.kernel.module;
              DM_VERITY = lib.kernel.module;
              DM_VERITY_VERIFY_ROOTHASH_SIG = option yes;
              DM_VERITY_FEC = option yes;
              SECONDARY_TRUSTED_KEYRING = lib.mkForce yes;
              SYSTEM_BLACKLIST_KEYRING = lib.mkForce yes;

              # fs-verity file integrity verification
              FS_VERITY = lib.mkForce yes;
              FS_VERITY_BUILTIN_SIGNATURES = lib.mkForce yes;
            };
          };

        linuxPackages_kcfi = prev.linuxPackagesFor final.linux_kcfi;
      })
    ];

    boot.kernelPackages = pkgs.linuxPackages_kcfi;
    boot.kernelParams = lib.mkDefault effectiveKernelParams;
  };
}
