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

# Set output directory for temp files
if [[ -n "$OUTPUT_DIR" ]]; then
  TEMP_OUTPUT_DIR="$OUTPUT_DIR"
else
  TEMP_OUTPUT_DIR="$(pwd)"
fi

# Run Trivy on Container Images if enabled
if [[ "$INPUT_TRIVY_IMAGE_ENABLED" == "true" ]]; then
    echo "Running Trivy on Container Images"
    IFS=',' read -ra DOCKER_IMAGES <<< "${INPUT_DOCKER_IMAGES}"
    for image in "${DOCKER_IMAGES[@]}"; do
        echo "Scanning image: $image"
        trivy image --scanners vuln --format json --output "$TEMP_OUTPUT_DIR/trivy_image_${image//\//_}.json" "$image" || :
    done
fi

# Run Trivy on Dockerfiles if enabled
if [[ "$INPUT_TRIVY_DOCKERFILE_ENABLED" == "true" ]]; then
    IFS=',' read -ra DOCKERFILES <<< "${INPUT_DOCKERFILES}"
    for dockerfile in "${DOCKERFILES[@]}"; do
        echo "Scanning Dockerfile: $dockerfile"
        trivy config --format json --output "$TEMP_OUTPUT_DIR/trivy_dockerfile_${dockerfile//\//_}.json" "$GITHUB_WORKSPACE/$dockerfile" || :
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
    trufflehog_cmd+=" --no-verification -j $GITHUB_WORKSPACE > $TEMP_OUTPUT_DIR/trufflehog_output.json"
    eval $trufflehog_cmd || :
fi

# POSIX-compatible file collection (replace mapfile)
scan_files=()
if [[ "$INPUT_SCAN_ALL" == "true" ]]; then
  while IFS= read -r file; do
    scan_files+=("$file")
  done < <(find . -type f \( -name '*.py' -o -name '*.go' -o -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' \))
elif [[ -n "$INPUT_SCAN_FILES" ]]; then
  IFS=',' read -ra scan_files <<< "$INPUT_SCAN_FILES"
else
  if [[ -d .git ]]; then
    while IFS= read -r file; do
      scan_files+=("$file")
    done < <(git diff --name-only HEAD~1 HEAD)
  else
    while IFS= read -r file; do
      scan_files+=("$file")
    done < <(find . -type f \( -name '*.py' -o -name '*.go' -o -name '*.js' -o -name '*.jsx' -o -name '*.ts' -o -name '*.tsx' \))
  fi
fi

# Separate files by language
python_files=()
go_files=()
js_files=()
for file in "${scan_files[@]}"; do
  case "$file" in
    *.py) python_files+=("$file") ;;
    *.go) go_files+=("$file") ;;
    *.js|*.jsx|*.ts|*.tsx) js_files+=("$file") ;;
  esac
done

# Run Bandit on Python files
if [[ "${#python_files[@]}" -gt 0 && "$INPUT_PYTHON_SAST_ENABLED" == "true" ]]; then
  echo "Running Bandit on Python files: ${python_files[*]}"
  bandit_cmd="bandit -f json -o $TEMP_OUTPUT_DIR/bandit_output.json ${python_files[*]}"
  if [[ -n "$BANDIT_EXCLUDE_DIR" ]]; then
    bandit_cmd+=" --exclude $BANDIT_EXCLUDE_DIR"
  fi
  if [[ -n "$BANDIT_RULES" ]]; then
    bandit_cmd+=" --skip $BANDIT_RULES"
  fi
  echo $bandit_cmd
  eval $bandit_cmd || :
fi

# Run Gosec on Go files
if [[ "${#go_files[@]}" -gt 0 && "$INPUT_GOLANG_SAST_ENABLED" == "true" ]]; then
  echo "Running Gosec on Go files: ${go_files[*]}"
  gosec_cmd="gosec -fmt json -out $TEMP_OUTPUT_DIR/gosec_output.json ${go_files[*]}"
  if [[ -n "$GOSEC_EXCLUDE_DIR" ]]; then
    gosec_cmd+=" -exclude-dir=$GOSEC_EXCLUDE_DIR"
  fi
  if [[ -n "$GOSEC_RULES" ]]; then
    gosec_cmd+=" -severity=$GOSEC_RULES"
  fi
  eval $gosec_cmd || :
fi

# ESLint rules setup (needed for JS/TS SAST)
ESLINT_EXCLUDE_DIR=${INPUT_ESLINT_EXCLUDE_DIR:-}
ESLINT_RULES=${INPUT_ESLINT_RULES:-}
if [[ -z "$ESLINT_RULES" ]]; then
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

# Run ESLint on JS/TS files
if [[ "${#js_files[@]}" -gt 0 && "${INPUT_JAVASCRIPT_SAST_ENABLED:-false}" == "true" ]]; then
  echo "Running ESLint on JS/TS files: ${js_files[*]}"
  eslint_cmd="npx --yes eslint --config $WORKSPACE/eslint.config.mjs ${js_files[*]} --ext .js,.jsx,.ts,.tsx --format json --output-file $TEMP_OUTPUT_DIR/eslint_output.json"
  if [[ -n "$ESLINT_EXCLUDE_DIR" ]]; then
    IFS=',' read -ra EXCLUDES <<< "$ESLINT_EXCLUDE_DIR"
    for exclude in "${EXCLUDES[@]}"; do
      eslint_cmd+=" --ignore-pattern $exclude"
    done
  fi
  eval $eslint_cmd || :
fi

# Move output files (no-op if already in correct place)
# Only cd in GitHub Actions, not local
if [ "$LOCAL_TESTING" != "true" ]; then
  cd "$WORKSPACE"
fi
# Run the Python script from the correct directory and path
python "$WORKSPACE/src/socket_external_tools_runner.py"
