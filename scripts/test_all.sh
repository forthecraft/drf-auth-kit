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

# Run tests based on coverage flag
if [ "$RUN_COVERAGE" = true ]; then
    echo "Running tests with coverage..."

    pytest --cov=auth_kit --cov-report= sandbox_extras/custom_auth

    pytest --cov=auth_kit --cov-append --cov-report= sandbox_extras/email_user

    pytest --cov=auth_kit --cov-append --cov-report= sandbox_extras/custom_username

    pytest --cov=auth_kit --cov-append --cov-report=term-missing sandbox
else
    echo "Running tests without coverage..."

    pytest sandbox_extras/custom_auth

    pytest sandbox_extras/email_user

    pytest sandbox_extras/custom_username

    pytest sandbox
fi
