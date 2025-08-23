# Use the official Python image as a base
FROM python:3.9
COPY src/socket_external_tools_runner.py /
COPY src/core /core
COPY entrypoint.sh /
ENV PATH=$PATH:/usr/local/go/bin

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Setup Golang
RUN curl -sfL https://go.dev/dl/go1.23.2.linux-amd64.tar.gz > go1.23.2.linux-amd64.tar.gz
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.2.linux-amd64.tar.gz

# Install system dependencies and Gosec
RUN apt-get update && \
    apt-get install -y curl git wget
RUN curl -sfL https://raw.githubusercontent.com/securego/gosec/master/install.sh  | sh -s -- -b /usr/local/bin v2.21.4

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.18.3

#Install Trufflehog
# Install trufflehog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Install Bandit using uv as a tool
RUN uv tool install bandit
ENV PATH="/root/.local/bin:$PATH"

# Install eslint
RUN apt-get update && apt-get install -y curl && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g eslint eslint-plugin-security @typescript-eslint/parser @typescript-eslint/eslint-plugin

# Install Socket CLI tools
RUN npm install -g socket
RUN uv tool install socketsecurity

# Copy the entrypoint script and make it executable
RUN chmod +x /entrypoint.sh


COPY pyproject.toml uv.lock /scripts/
# Install Python dependencies using uv
WORKDIR /scripts
RUN uv sync --frozen
ENV PATH="/scripts/.venv/bin:$PATH"

# Define entrypoint
ENTRYPOINT ["/entrypoint.sh"]
