# Contributing to OstrichPKI

## Semantic Versioning

This project follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR version** (X.0.0): Incompatible API changes
- **MINOR version** (0.X.0): New functionality in a backward-compatible manner
- **PATCH version** (0.0.X): Backward-compatible bug fixes

### Version Update Guidelines

**When to bump versions:**

1. **feat:** commits → Bump MINOR version (0.2.0 → 0.3.0)
   - New features
   - New API endpoints
   - New service implementations
   - New command-line commands

2. **fix:** commits → Bump PATCH version (0.2.0 → 0.2.1)
   - Bug fixes
   - Security patches
   - Performance improvements (without new features)

3. **Breaking changes** → Bump MAJOR version (0.2.0 → 1.0.0)
   - API changes that break backward compatibility
   - Removed functionality
   - Changed behavior that affects existing users

### Version Update Process

1. **Update workspace version** in root `Cargo.toml`:
   ```toml
   [workspace.package]
   version = "0.X.0"  # Update this line
   ```

2. **Update CHANGELOG.md** with new release section:
   - Add new version section under `## [Unreleased]`
   - Use proper markdown formatting (##### for crate names)
   - Include all features, changes, fixes, and technical details
   - Update version links at bottom of file

3. **Commit with chore: prefix**:
   ```bash
   git commit -m "chore: bump version to 0.X.0 and update CHANGELOG"
   ```

## Changelog Guidelines

Follow [Keep a Changelog](https://keepachangelog.com/) format:

### Structure

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes to existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security vulnerabilities fixed
```

### Markdown Formatting Rules

1. **Use proper heading levels:**
   - `####` for phase/category headings
   - `#####` for crate names (not bold text)

2. **Add blank lines:**
   - Before and after lists
   - Between sections

3. **Crate documentation:**
   ```markdown
   ##### ostrich-ca

   - Feature one
   - Feature two
   ```

## Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature (bumps MINOR version)
- **fix**: Bug fix (bumps PATCH version)
- **docs**: Documentation only
- **style**: Code style changes (formatting, no code change)
- **refactor**: Code refactoring (no feature/fix)
- **perf**: Performance improvement
- **test**: Adding tests
- **chore**: Maintenance (dependencies, version bumps)
- **ci**: CI/CD changes

### Scope

Use crate names or service names:
- `feat(ca): add certificate issuance`
- `fix(ocsp): handle missing certificates`
- `docs(readme): update installation guide`

### Breaking Changes

Add `BREAKING CHANGE:` in footer:

```
feat(api): remove deprecated endpoint

BREAKING CHANGE: The /old-endpoint has been removed.
Use /new-endpoint instead.
```

## Development Workflow

1. **Create feature branch**:
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make changes and commit**:
   ```bash
   cargo fmt --all
   cargo clippy --all-targets -- -D warnings
   cargo test --all
   git commit -m "feat(scope): add feature"
   ```

3. **Before merging**:
   - Run all tests
   - Run clippy with -D warnings
   - Format all code
   - Update CHANGELOG.md if needed
   - Bump version if adding features

4. **Merge to main**:
   ```bash
   git checkout main
   git merge feature/my-feature
   ```

## Code Quality Standards

All code must pass:

```bash
# Format check
cargo fmt --all --check

# Linting
cargo clippy --all-targets -- -D warnings

# Tests
cargo test --all

# Build check
cargo check --all
```

## Documentation

- Update CHANGELOG.md for user-facing changes
- Add rustdoc comments for public APIs
- Update README.md for major features
- RFC compliance must be documented in code comments

## Security

- Follow NIST 800-53 Rev 5 guidelines
- Document security controls in code
- Report vulnerabilities privately
- Include CVE fixes in CHANGELOG security section
