# Repository Guidelines

## Project Structure & Modules
- `flake.nix` defines outputs; `modules/` exports `hardenedKernel`, `hardenedUserspace`, `verity`, `fsverity`, `systemdHardening`, and the `all`/`default` aggregate. Keep new modules small and security-focused.
- `tests/default.nix` houses NixOS VM tests and config-eval checks; mirror new features with dedicated tests here.
- `justfile` is the task runner; prefer `just` targets over raw commands for consistency and reproducibility.

## Build, Test, and Development Commands
- Enter the dev shell: `nix develop` (or `direnv allow` if enabled).
- Quick check (eval only): `just check-fast`.
- Full matrix (VMs + eval): `just check` or `nix flake check`.
- Targeted builds: `just build <check>` (e.g., `userspace`, `fsverity`); interactive VM debug: `just test-interactive <test>`.
- Formatting: `just fmt` (writes) or `just fmt-check` (CI-safe).

## Coding Style & Naming Conventions
- Language: Nix; indent two spaces; prefer explicit attribute names over globals. Keep options under the `vitrify.*` namespace and document defaults in module options.
- Run `nixfmt` before committing; do not bypass `gofmt/rustfmt/formatter` equivalents if you add other languages.
- Security by default: no hardcoded secrets, no permissive fallbacks. Validate user-provided paths, booleans, and enums using `lib.types`.

## Testing Guidelines
- Add both evaluation and VM coverage: extend `checks` in `flake.nix` and add scenarios in `tests/default.nix`. Tests should assert hardened values (e.g., sysctls, AppArmor, verity setup) and fail closed on errors.
- Local loop: `just check-fast` during development; `just check` before PRs. Capture failures with `-L` logs when reporting.

## Commit & Pull Request Guidelines
- Commit messages: short, imperative, lowercase scope optional (e.g., `Add fs-verity defaults`, `Fix systemd hardening test`). Avoid noise like “update”.
- PRs should include: summary of change, security impact (tighter/looser), tests run with command output, linked issue/decision record, and any compatibility notes (e.g., module signing requirements).

## Security & Configuration Tips
- Default to least privilege: keep `lockdown`, module signing, and restricted sysctls enabled unless a documented compatibility need exists.
- Never commit keys or hashes; reference them via paths/options and expect consumers to supply secrets through Nix inputs or secure stores.
- Favor reproducibility: avoid host-specific paths; keep new options deterministic and disable auto-detection unless explicitly justified.
