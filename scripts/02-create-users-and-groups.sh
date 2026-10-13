#!/usr/bin/env bash
#
# Phase 1 — Create Identity Center users and groups
#
# Models a small organisation:
#   Admins      — admin
#   Developers  — dev1, dev2
#   Auditors    — auditor
#
# Permission sets are assigned to GROUPS, never directly to users. Access then
# changes by moving someone between groups rather than editing policy, which is
# what makes access reviews tractable at scale.
#
# All addresses use Gmail plus-addressing so every simulated user delivers to
# one real inbox while remaining unique, as the identity store requires.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=config.env
source "$SCRIPT_DIR/config.env"
IDS="$IDENTITY_STORE_ID"

make_group () {
  aws identitystore create-group \
    --identity-store-id "$IDS" \
    --display-name "$1" \
    --description "$2" \
    --query GroupId --output text
}

make_user () {
  local username="$1" display="$2" given="$3" family="$4"
  aws identitystore create-user \
    --identity-store-id "$IDS" \
    --user-name "$username" \
    --display-name "$display" \
    --name "GivenName=$given,FamilyName=$family" \
    --emails "Value=${EMAIL_BASE}+${username}@gmail.com,Type=work,Primary=true" \
    --query UserId --output text
}

add_to_group () {
  aws identitystore create-group-membership \
    --identity-store-id "$IDS" \
    --group-id "$1" \
    --member-id UserId="$2" \
    --query MembershipId --output text > /dev/null
}

echo "Creating groups..."
G_ADMIN=$(make_group "Admins"     "Platform and security administrators")
G_DEV=$(make_group   "Developers" "Application developers")
G_AUD=$(make_group   "Auditors"   "Compliance and audit reviewers")

echo "Creating users..."
U_ADMIN=$(make_user admin   "Admin User"   Admin   User)
U_DEV1=$(make_user  dev1    "Dev One"      Dev     One)
U_DEV2=$(make_user  dev2    "Dev Two"      Dev     Two)
U_AUD=$(make_user   auditor "Auditor User" Auditor User)

echo "Assigning memberships..."
add_to_group "$G_ADMIN" "$U_ADMIN"
add_to_group "$G_DEV"   "$U_DEV1"
add_to_group "$G_DEV"   "$U_DEV2"
add_to_group "$G_AUD"   "$U_AUD"

echo
echo "Group IDs — keep these, the account assignment step needs them:"
printf '%-12s %s\n' "Admins"     "$G_ADMIN"
printf '%-12s %s\n' "Developers" "$G_DEV"
printf '%-12s %s\n' "Auditors"   "$G_AUD"
