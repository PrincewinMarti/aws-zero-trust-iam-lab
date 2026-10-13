#!/usr/bin/env bash
#
# Phase 1 — Create IAM Identity Center permission sets
#
# Creates three permission sets modelling a small team:
#   AdminAccess      — full administrative access (platform/security team)
#   DeveloperAccess  — power user, but cannot modify IAM (developers)
#   AuditorAccess    — read-only security audit access (compliance/GRC)
#
# Session duration is capped at 4 hours rather than the AWS default, so
# credentials expire on the same working day they were issued.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.env
source "$SCRIPT_DIR/config.env"

create_permission_set () {
  local name="$1" description="$2" policy_arn="$3"

  local ps_arn
  ps_arn=$(aws sso-admin create-permission-set \
    --instance-arn "$INSTANCE_ARN" \
    --name "$name" \
    --description "$description" \
    --session-duration PT4H \
    --query 'PermissionSet.PermissionSetArn' \
    --output text)

  aws sso-admin attach-managed-policy-to-permission-set \
    --instance-arn "$INSTANCE_ARN" \
    --permission-set-arn "$ps_arn" \
    --managed-policy-arn "$policy_arn"

  printf '%-18s %s\n' "$name" "$ps_arn"
}

echo "Creating permission sets..."
echo

create_permission_set \
  "AdminAccess" \
  "Full administrative access" \
  "arn:aws:iam::aws:policy/AdministratorAccess"

create_permission_set \
  "DeveloperAccess" \
  "Developer access to build and deploy, excluding IAM changes" \
  "arn:aws:iam::aws:policy/PowerUserAccess"

create_permission_set \
  "AuditorAccess" \
  "Read-only access for security audit and compliance review" \
  "arn:aws:iam::aws:policy/SecurityAudit"

echo
echo "Done. Verify with:"
echo "  aws sso-admin list-permission-sets --instance-arn $INSTANCE_ARN"
