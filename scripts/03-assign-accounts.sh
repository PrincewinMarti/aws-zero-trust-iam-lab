#!/usr/bin/env bash
#
# Phase 1 — Assign permission sets to groups, per account
#
# Access matrix:
#
#   Group        Management        Dev               Prod
#   ---------    --------------    --------------    --------------
#   Admins       AdminAccess       AdminAccess       AdminAccess
#   Developers   (none)            DeveloperAccess   (none)
#   Auditors     (none)            AuditorAccess     AuditorAccess
#
# Two deliberate gaps:
#
#   Developers have NO access to Prod at all. Not read-only — nothing. This is
#   the boundary tested at the end of Phase 1 and extended with tag conditions
#   in Phase 2.
#
#   Only Admins reach the Management account, since it holds the SCPs and the
#   organisation configuration. Access there is effectively access everywhere.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.env
source "$SCRIPT_DIR/config.env"

assign () {
  local account="$1" permission_set="$2" group="$3" label="$4"
  aws sso-admin create-account-assignment \
    --instance-arn "$INSTANCE_ARN" \
    --target-id "$account" \
    --target-type AWS_ACCOUNT \
    --permission-set-arn "$permission_set" \
    --principal-type GROUP \
    --principal-id "$group" \
    --query 'AccountAssignmentCreationStatus.Status' --output text > /dev/null
  echo "  $label"
}

echo "Assigning access..."
assign "$ACC_MGMT" "$PS_ADMIN" "$G_ADMIN" "Admins     -> Management (AdminAccess)"
assign "$ACC_DEV"  "$PS_ADMIN" "$G_ADMIN" "Admins     -> Dev        (AdminAccess)"
assign "$ACC_PROD" "$PS_ADMIN" "$G_ADMIN" "Admins     -> Prod       (AdminAccess)"
assign "$ACC_DEV"  "$PS_DEV"   "$G_DEV"   "Developers -> Dev        (DeveloperAccess)"
assign "$ACC_DEV"  "$PS_AUDIT" "$G_AUD"   "Auditors   -> Dev        (AuditorAccess)"
assign "$ACC_PROD" "$PS_AUDIT" "$G_AUD"   "Auditors   -> Prod       (AuditorAccess)"

echo
echo "Note: Developers are intentionally not assigned to Prod."
