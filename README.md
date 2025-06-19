# Security Tools Scanning

The purpose of this action is to run various security tools, process their output, and then comment the results on a PR. It is expected to only run this on PRs

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

          # Trivy Configuration
          docker_images: "image:latest,test/image2:latest"
          dockerfiles: "Dockerfile,relative/path/Dockerfile"

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
  -e "SOCKET_SCM_DISABLED=true" \
  -e "INPUT_SOCKET_CONSOLE_MODE=json" \
  socketdev/security-wrapper
```

**Notes:**
- You can adjust the environment variables to enable/disable specific scanners.
- For image scanning, Docker-in-Docker must be enabled, and you may need to add a `docker pull` step before running.
- Results will be printed to the console or output as JSON, depending on `INPUT_SOCKET_CONSOLE_MODE`.
- You can also run the wrapper directly with Bash and Python for rapid local development (see `entrypoint.sh`).
