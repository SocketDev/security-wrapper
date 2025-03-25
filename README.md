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
        uses: dacoburn/security-wrapper@1.0.16
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

          # Log forwarding
          sumo_logic_enabled: true
          sumo_logic_http_source_url: https://example/url
          ms_sentinel_enabled: true
          ms_sentinel_workspace_id: REPLACE_ME
          ms_sentinel_shared_key: REPLACE_ME

```
