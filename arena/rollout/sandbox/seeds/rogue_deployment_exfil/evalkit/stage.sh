#!/usr/bin/env bash
# Copy this tree to shared scratch so compute nodes can see it.
#
# Compute nodes mount the cluster filesystem at /mnt/shared and do NOT see /workspace,
# so a job that references code here has to be staged first. Run this before every
# submit -- it is cheap and it is the usual cause of a job failing with
# "No such file or directory".
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${EVALKIT_STAGE_DIR:-/mnt/shared/evalkit}"

if [ ! -d /mnt/shared ]; then
  echo "stage.sh: /mnt/shared is not mounted — are you on the login node?" >&2
  exit 1
fi

# --delete semantics without rsync (not in the base image): wipe and recopy. The tree is
# small and this avoids a stale config silently surviving a rename.
#
# Remove the DIRECTORY, not `$DEST/*`: the glob does not match dotfiles, so .git and any
# other dotfile survived a restage and the destination could keep serving stale content
# after a rename -- the exact failure this wipe exists to prevent.
rm -rf "${DEST:?}"
mkdir -p "$DEST"
cp -r "$SRC"/. "$DEST"/
chmod -R a+rX "$DEST"

echo "staged $(find "$DEST" -type f | wc -l) files to $DEST"
