# Security Tools Scanning

The purpose of this action is to run various security tools, process their output, and then comment the results on a PR. It is expected to only run this on PRs.

## New: Consolidated Socket Facts Format

Starting with version 2.0.0, all security tool results are consolidated into a unified `.socket.facts.json` format. This provides:

- **Unified Processing**: All security findings in a single, consistent format
- **Enhanced Integration**: Easier integration with Socket's dependency analysis
- **Custom Components**: Support for organization-specific component types
- **Backward Compatibility**: Existing workflows continue to work unchanged

The consolidated format extends Socket's dependency data with external security findings from SAST scanners, secret scanners, and container scanners.

## Supported Security Tools

- **Bandit** - Python SAST analysis
- **Gosec** - Golang SAST analysis  
- **ESLint** - JavaScript/TypeScript SAST analysis
- **Trivy** - Container image and Dockerfile vulnerability scanning
- **Trufflehog** - Secret scanning
- **Socket** - Dependency reachability analysis and supply chain risk scanning
  - Uses `socket scan reach` to identify which vulnerable code paths are actually reachable in your application
  - Includes stack trace information for reachable vulnerabilities to help with remediation
  - Note: This is different from Socket SCA scanning which analyzes all dependencies

## Example Usage

```yaml
name: Security Scan Workflow
on:
  pull_request:
    types: [opened, synchronize, edited]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
      contents: read

    steps:
      - name: Checkout code
        uses: actions/checkout@v4.2.1
      
      - name: Run Security Scan and Comment Action
        uses: SocketDev/security-wrapper@1.0.17
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}

          # Enable settings
          python_sast_enabled: true
          golang_sast_enabled: true
          javascript_sast_enabled: true
          dockerfile_enabled: true
          image_enabled: true
          secret_scanning_enabled: true
          socket_scanning_enabled: true

          # Trivy Configuration
          docker_images: "image:latest,test/image2:latest"
          dockerfiles: "Dockerfile,relative/path/Dockerfile"

          # Socket Configuration
          socket_org: "your-socket-org"  # Required when socket_scanning_enabled is true
          socket_api_key: ${{ secrets.SOCKET_API_KEY }}

          # Exclusion settings
          trufflehog_exclude_dir: "node_modules/*,vendor,.git/*,.idea"
          trufflehog_show_unverified: False
          bandit_exclude_dir: "tests,migrations,tests,test,.venv,venv"
          bandit_rules: "B101,B102,B105,B106,B107,B110,B603,B605,B607"
          gosec_rules: "medium"
          gosec_exclude_dir: "tests,migrations,tests,test,.venv,venv"
          eslint_rules: >
            security/detect-eval-with-expression,
            security/detect-non-literal-require,
            security/detect-non-literal-fs-filename,
            security/detect-buffer-noassert,
            security/detect-new-buffer,
            security/detect-unsafe-regex,
            security/detect-disable-mustache-escape,
            security/detect-no-csrf-before-method-override,
            security/detect-pseudoRandomBytes,
            security/detect-possible-timing-attacks,
            security/detect-bidi-characters,
            security/detect-child-process,
            security/detect-non-literal-regexp,
            security/detect-object-injection

          # Log output
          sumo_logic_enabled: true
          sumo_logic_http_source_url: https://example/url
          ms_sentinel_enabled: true
          ms_sentinel_workspace_id: REPLACE_ME
          ms_sentinel_shared_key: REPLACE_ME

          # Scan scope settings
          scan_all: false   # Set to true to always scan the whole directory
          scan_files: ""    # Comma-separated list of files to scan (overrides git diff)
```

## Local Development & Testing

You can run the security-wrapper locally using Docker. This is useful for testing changes or scanning code outside of GitHub Actions.

### Prerequisites

This project uses [uv](https://docs.astral.sh/uv/) for Python package management. Install it with:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Local Python Development

For local Python development without Docker:

```sh
# Install dependencies
uv sync

# Run the security wrapper directly
uv run python src/socket_external_tools_runner.py
```

### Build the Docker Image

```sh
git clone git@github.com:SocketDev/security-wrapper.git

# Build the Docker image
docker build -t socketdev/security-wrapper .
```

### Run the Security Wrapper Locally

```sh
docker run --rm --name security-wrapper \
  -v "$PWD:/code" \
  -e "GIT_REPO=socketdev-demo/sast-testing" \
  -e "GITHUB_REPOSITORY=socketdev-demo/sast-testing" \
  -e "GITHUB_WORKSPACE=/code" \
  -e "INPUT_CONSOLE_ENABLED=true" \
  # Uncomment and set if you want to scan images (requires Docker-in-Docker)
  # -e "INPUT_DOCKER_IMAGES=trickyhu/sigsci-rule-editor:latest,socketdev/cli:latest" \
  -e "INPUT_DOCKERFILE_ENABLED=true" \
  -e "INPUT_DOCKERFILES=Dockerfile,Dockerfile.sigsci" \
  -e "INPUT_ESLINT_SAST_ENABLED=true" \
  -e "INPUT_FINDING_SEVERITIES=critical" \
  -e "INPUT_GOSEC_SAST_ENABLED=true" \
  -e "INPUT_IMAGE_ENABLED=true" \
  -e "INPUT_PYTHON_SAST_ENABLED=true" \
  -e "PYTHONUNBUFFERED=1" \
  -e "INPUT_SECRET_SCANNING_ENABLED=true" \
  -e "INPUT_SOCKET_SCANNING_ENABLED=true" \
  -e "INPUT_SOCKET_ORG=your-socket-org" \  # Required when socket_scanning_enabled is true
  -e "INPUT_SOCKET_API_KEY=your-socket-api-key" \
  -e "SOCKET_SCM_DISABLED=true" \
  -e "INPUT_SOCKET_CONSOLE_MODE=json" \
  socketdev/security-wrapper
```

## Version Management

This project uses automated version management with uv and pyproject.toml:

- **Version Source**: `pyproject.toml` is the source of truth for version numbers
- **Runtime Version**: `src/version.py` is auto-synced and imported by the application
- **Pre-commit Hooks**: Automatic version checking and bumping via `.hooks/version-check.py`

### Setup Version Management

```sh
# Install the pre-commit hook
python3 .hooks/setup.py --install-hook

# Manual version checking
python3 .hooks/version-check.py        # Auto-bump patch version if unchanged
python3 .hooks/version-check.py --dev  # Create dev versions (1.0.18.dev1, etc.)
```

**Notes:**
- You can adjust the environment variables to enable/disable specific scanners.
- For image scanning, Docker-in-Docker must be enabled, and you may need to add a `docker pull` step before running.
- Results will be printed to the console or output as JSON, depending on `INPUT_SOCKET_CONSOLE_MODE`.
- You can also run the wrapper directly with Bash and Python/uv for rapid local development (see `entrypoint.sh`).
