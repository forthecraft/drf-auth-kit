#!/usr/bin/env bash

# Function to show usage
show_usage() {
    echo "Usage: $0 [--cov]"
    echo "  --cov    Run tests with coverage reporting"
    echo "  (no args) Run tests without coverage"
    exit 1
}

# Check arguments
RUN_COVERAGE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --cov)
            RUN_COVERAGE=true
            shift
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            ;;
    esac
done

# Schema tests reload modules and mutate shared settings state via
# override_auth_kit_settings + reload(), which is not safe with xdist
# parallel workers. They must run without xdist (-o "addopts=").
SCHEMA_OPTS='-o addopts='

# Every group must run even when an earlier one fails, so coverage stays
# complete and all failures are visible in one pass -- but the script has to
# still exit non-zero, or a red group hides behind the last green one.
FAILED_GROUPS=()

run_group() {
    local label=$1
    shift
    if ! "$@"; then
        FAILED_GROUPS+=("$label")
    fi
}

report() {
    if [ ${#FAILED_GROUPS[@]} -ne 0 ]; then
        echo
        echo "FAILED test groups (${#FAILED_GROUPS[@]}):"
        printf '  - %s\n' "${FAILED_GROUPS[@]}"
        exit 1
    fi
    echo
    echo "All test groups passed."
}

# Run tests based on coverage flag
if [ "$RUN_COVERAGE" = true ]; then
    echo "Running tests with coverage..."

    run_group custom_auth pytest --cov=auth_kit --cov-report= sandbox_extras/custom_auth

    run_group email_user pytest --cov=auth_kit --cov-append --cov-report= sandbox_extras/email_user

    run_group custom_username pytest --cov=auth_kit --cov-append --cov-report= sandbox_extras/custom_username

    run_group axes pytest --cov=auth_kit --cov-append --cov-report= sandbox_extras/integrations/axes

    run_group core_schema pytest --cov=auth_kit --cov-append --cov-report= $SCHEMA_OPTS sandbox/test_schema/core_schema

    run_group mfa_schema pytest --cov=auth_kit --cov-append --cov-report= $SCHEMA_OPTS sandbox/test_schema/mfa_schema

    run_group social_schema pytest --cov=auth_kit --cov-append --cov-report= $SCHEMA_OPTS sandbox/test_schema/social_schema

    run_group test_auth_kit pytest --cov=auth_kit --cov-append --cov-report=xml --cov-report=term-missing sandbox/test_auth_kit
else
    echo "Running tests without coverage..."

    run_group custom_auth pytest sandbox_extras/custom_auth

    run_group email_user pytest sandbox_extras/email_user

    run_group custom_username pytest sandbox_extras/custom_username

    run_group axes pytest sandbox_extras/integrations/axes

    run_group core_schema pytest $SCHEMA_OPTS sandbox/test_schema/core_schema

    run_group mfa_schema pytest $SCHEMA_OPTS sandbox/test_schema/mfa_schema

    run_group social_schema pytest $SCHEMA_OPTS sandbox/test_schema/social_schema

    run_group test_auth_kit pytest sandbox/test_auth_kit
fi

report
