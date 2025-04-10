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
if [[ "${INPUT_JAVASCRIPT_SAST_ENABLED:-false}" == "true" ]]; then
  echo "Running ESLint"
  ESLINT_EXCLUDE_DIR=${INPUT_ESLINT_EXCLUDE_DIR:-}
  ESLINT_RULES=${INPUT_ESLINT_RULES:-}

  if [[ -z "$ESLINT_RULES" ]]; then
    echo "Using default ESLint rules"
    ESLINT_RULES=$(cat <<'EOF'
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
security/detect-object-injection,
@typescript-eslint/no-implied-eval,
@typescript-eslint/no-throw-literal,
@typescript-eslint/no-misused-promises,
@typescript-eslint/no-unsafe-argument,
@typescript-eslint/no-unsafe-assignment,
@typescript-eslint/no-unsafe-call,
@typescript-eslint/no-unsafe-member-access,
@typescript-eslint/no-unsafe-return,
@typescript-eslint/ban-ts-comment,
@typescript-eslint/no-explicit-any,
@typescript-eslint/explicit-module-boundary-types,
@typescript-eslint/no-floating-promises,
@typescript-eslint/no-for-in-array,
@typescript-eslint/no-misused-new,
@typescript-eslint/no-non-null-asserted-optional-chain,
@typescript-eslint/no-non-null-assertion,
@typescript-eslint/no-unnecessary-type-assertion,
@typescript-eslint/prefer-optional-chain,
@typescript-eslint/prefer-nullish-coalescing,
@typescript-eslint/restrict-plus-operands,
@typescript-eslint/restrict-template-expressions,
@typescript-eslint/require-await,
@typescript-eslint/unbound-method,
@typescript-eslint/array-type,
@typescript-eslint/ban-types,
@typescript-eslint/consistent-type-assertions,
@typescript-eslint/consistent-type-definitions,
@typescript-eslint/explicit-function-return-type,
@typescript-eslint/no-empty-interface,
@typescript-eslint/no-inferrable-types,
@typescript-eslint/no-invalid-void-type,
@typescript-eslint/no-redeclare,
@typescript-eslint/no-shadow,
@typescript-eslint/no-unused-vars,
@typescript-eslint/no-use-before-define,
@typescript-eslint/prefer-as-const
EOF
)
  fi

  # Convert rule list to JSON map: "rule-name": "error"
  ESLINT_RULES_JSON=$(echo "$ESLINT_RULES" | tr ',' '\n' | sed '/^\s*$/d' | awk '{printf "\"%s\": \"error\",\n", $0}' | sed '$s/,$//')

  if [[ ! -f "$WORKSPACE/eslint.config.mjs" ]]; then
    echo "Adding fallback ESLint config"
    cat <<EOF > "$WORKSPACE/eslint.config.mjs"
export default [
  {
    files: ['**/*.js', '**/*.jsx', '**/*.ts', '**/*.tsx'],
    rules: {
$ESLINT_RULES_JSON
    },
  },
];
EOF
  fi

  eslint_cmd="npx --yes eslint --config $WORKSPACE/eslint.config.mjs $WORKSPACE --ext .js,.jsx,.ts,.tsx --format json --output-file $OUTPUT_DIR/eslint_output.json"

  if [[ -n "$ESLINT_EXCLUDE_DIR" ]]; then
    IFS=',' read -ra EXCLUDES <<< "$ESLINT_EXCLUDE_DIR"
    for exclude in "${EXCLUDES[@]}"; do
      eslint_cmd+=" --ignore-pattern $exclude"
    done
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
    echo $bandit_cmd
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
if [ "$LOCAL_TESTING" != "true" ]; then
  cd /
fi
mv /tmp/*.json .
if [ "$LOCAL_TESTING" != "true" ]; then
  python socket_external_tools_runner.py
else
  python socket_external_tools_runner.py
fi
