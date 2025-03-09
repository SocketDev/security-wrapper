#!/bin/bash

# Set default values for exclusion and rule options if not provided
TRUFFLEHOG_EXCLUDE_DIR=${INPUT_TRUFFLEHOG_EXCLUDE_DIR:-}
TRUFFLEHOG_RULES=${INPUT_TRUFFLEHOG_RULES:-}

BANDIT_EXCLUDE_DIR=${INPUT_BANDIT_EXCLUDE_DIR:-}
BANDIT_RULES=${INPUT_BANDIT_RULES:-}

GOSEC_EXCLUDE_DIR=${INPUT_GOSEC_EXCLUDE_DIR:-}
GOSEC_RULES=${INPUT_GOSEC_RULES:-}

TRIVY_EXCLUDE_DIR=${INPUT_TRIVY_EXCLUDE_DIR:-}
TRIVY_RULES=${INPUT_TRIVY_RULES:-}

# Run ESLint (JavaScript SAST) if enabled
if [[ "$INPUT_JAVASCRIPT_SAST_ENABLED" == "true" ]]; then
    echo "Running ESLint"
    ESLINT_EXCLUDE_DIR=${INPUT_ESLINT_EXCLUDE_DIR:-}
    ESLINT_RULES=${INPUT_ESLINT_RULES:-}

    eslint_cmd="npx eslint $GITHUB_WORKSPACE --ext .js,.jsx --format json --output-file /tmp/eslint_output.json"
    if [[ -n "$ESLINT_EXCLUDE_DIR" ]]; then
      eslint_cmd+=" --ignore-pattern $ESLINT_EXCLUDE_DIR"
    fi
    if [[ -n "$ESLINT_RULES" ]]; then
      eslint_cmd+=" --rule \"$ESLINT_RULES\""
    fi
    eval $eslint_cmd || :
fi

# Run Bandit (Python SAST) if enabled
if [[ "$INPUT_PYTHON_SAST_ENABLED" == "true" ]]; then
    echo "Running Bandit"
    bandit_cmd="bandit -r $GITHUB_WORKSPACE -f json -o /tmp/bandit_output.json"
    if [[ -n "$BANDIT_EXCLUDE_DIR" ]]; then
      bandit_cmd+=" --exclude $BANDIT_EXCLUDE_DIR"
    fi
    if [[ -n "$BANDIT_RULES" ]]; then
      bandit_cmd+=" --skip $BANDIT_RULES"
    fi
    eval $bandit_cmd || :
fi

# Run Gosec (Golang SAST) if enabled
if [[ "$INPUT_GOLANG_SAST_ENABLED" == "true" ]]; then
    echo "Running Gosec"
    gosec_cmd="gosec -fmt json -out /tmp/gosec_output.json "
    if [[ -n "$GOSEC_EXCLUDE_DIR" ]]; then
      gosec_cmd+=" -exclude-dir=$GOSEC_EXCLUDE_DIR"
    fi
    if [[ -n "$GOSEC_RULES" ]]; then
      gosec_cmd+=" -severity=$GOSEC_RULES"
    fi
    gosec_cmd+=" $GITHUB_WORKSPACE/..."
    eval $gosec_cmd || :
fi

# Run Trivy on Container Images if enabled
if [[ "$INPUT_TRIVY_IMAGE_ENABLED" == "true" ]]; then
    echo "Running Trivy on Container Images"
    IFS=',' read -ra DOCKER_IMAGES <<< "${INPUT_DOCKER_IMAGES}"
    for image in "${DOCKER_IMAGES[@]}"; do
        echo "Scanning image: $image"
        trivy image --scanners vuln --format json --output "/tmp/trivy_image_${image//\//_}.json" "$image" || :
    done
fi

# Run Trivy on Dockerfiles if enabled
if [[ "$INPUT_TRIVY_DOCKERFILE_ENABLED" == "true" ]]; then
    IFS=',' read -ra DOCKERFILES <<< "${INPUT_DOCKERFILES}"
    for dockerfile in "${DOCKERFILES[@]}"; do
        echo "Scanning Dockerfile: $dockerfile"
        trivy config --format json --output "/tmp/trivy_dockerfile_${dockerfile//\//_}.json" "$GITHUB_WORKSPACE/$dockerfile" || :
    done
fi

# Run Secret Scanning (Trufflehog) if enabled
if [[ "$INPUT_SECRET_SCANNING_ENABLED" == "true" ]]; then
    echo "Running Secret Scanning with Trufflehog"
    trufflehog_cmd="trufflehog filesystem "
    TRUFFLEHOG_EXCLUDE_FILE=$(mktemp)
    if [[ -n "$TRUFFLEHOG_EXCLUDE_DIR" ]]; then
      IFS=',' read -ra EXCLUDE_DIRS <<< "$TRUFFLEHOG_EXCLUDE_DIR"
      for dir in "${EXCLUDE_DIRS[@]}"; do
        echo "$dir" >> "$TRUFFLEHOG_EXCLUDE_FILE"
      done
      trufflehog_cmd+=" -x $TRUFFLEHOG_EXCLUDE_FILE"
    fi
    if [[ -n "$TRUFFLEHOG_RULES" ]]; then
      trufflehog_cmd+=" --rules $TRUFFLEHOG_RULES"
    fi
    trufflehog_cmd+=" --no-verification -j $GITHUB_WORKSPACE > /tmp/trufflehog_output.json"
    eval $trufflehog_cmd || :
fi

# Execute the custom Python script to process findings
#cd /
mv /tmp/*.json .
#python socket_external_tools_runner.py
