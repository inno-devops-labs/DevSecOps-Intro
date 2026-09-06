#!/usr/bin/env bash
# Extract and optionally run every fenced shell block of a lab spec.
#
#   tools/verify-lab.sh 2           list the blocks with their line numbers
#   tools/verify-lab.sh 2 --run     run them in order, stop at the first failure
#
# Directives go on the line above the fence:
#   <!-- verify:skip reason -->   do not run: student-fork commands, host kernel,
#                                 KVM, anything destructive
#   <!-- verify:wait 25 -->       wait N seconds first, where the lab text tells a
#                                 human to wait for a service to come up
#   <!-- verify:nonzero-ok -->    a non-zero exit is the expected outcome, as with a
#                                 scanner that exits 1 because it found something
#
# Blocks that would change the machine outside this repo (git config --global,
# sudo, package installs, writes under $HOME) are refused automatically, marked
# GUARD, whether or not the author remembered a skip marker.
#
# Portable to bash 3.2 (stock macOS): no mapfile, no associative arrays.
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LAB=${1:-}
MODE=${2:-list}

if [ -z "$LAB" ]; then
  echo "usage: tools/verify-lab.sh <lab-number> [--run]" >&2
  exit 2
fi

SPEC="$ROOT/labs/lab$LAB.md"
[ -f "$SPEC" ] || { echo "no such lab spec: $SPEC" >&2; exit 2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/verify-lab$LAB.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

awk -v out="$WORK" '
  /^<!-- verify:(skip|wait|nonzero-ok)/ { marker = $0; next }
  /^```(bash|sh|console)$/ && !inblock {
    inblock = 1; n++; start = NR
    file = sprintf("%s/block-%03d.sh", out, n)
    printf "%d\t%d\t%s\n", n, start, (marker == "" ? "-" : marker) >> (out "/manifest")
    marker = ""
    next
  }
  /^```/ && inblock { inblock = 0; close(file); next }
  inblock { print >> file }
  !inblock && $0 !~ /^$/ { marker = "" }
' "$SPEC"

[ -f "$WORK/manifest" ] || { echo "no shell blocks found in labs/lab$LAB.md"; exit 0; }

total=$(wc -l < "$WORK/manifest" | tr -d ' ')
echo "labs/lab$LAB.md: $total shell blocks"
echo

failed=0
ran=0
while IFS="$(printf '\t')" read -r n start marker; do
  file=$(printf "%s/block-%03d.sh" "$WORK" "$n")
  first=$(head -1 "$file")
  # Never execute a block that reaches outside the repository. The author who
  # forgets the skip marker is exactly the person this protects.
  if grep -qE 'git config --(global|system)|(^|[^-])\bsudo\b|pip[x3]* install|apt(-get)? install|brew install|npm i(nstall)? -g|>> *~/|> *~/|rm -rf +[~/]' "$file"; then
    printf "  %2s  line %-5s GUARD %s\n" "$n" "$start" "$first"
    printf "        changes the machine outside this repo; run it by hand if you must\n"
    continue
  fi
  case "$marker" in
    *verify:skip*)
      printf "  %2s  line %-5s SKIP  %s\n" "$n" "$start" "$first"
      continue ;;
    *verify:wait*)
      wait_for=$(echo "$marker" | sed -n 's/.*verify:wait *\([0-9][0-9]*\).*/\1/p')
      nonzero_ok="" ;;
    *verify:nonzero-ok*)
      wait_for=""
      nonzero_ok=1 ;;
    *)
      wait_for=""
      nonzero_ok="" ;;
  esac
  if [ "$MODE" != "--run" ]; then
    printf "  %2s  line %-5s      %s\n" "$n" "$start" "$first"
    continue
  fi
  if [ -n "$wait_for" ]; then
    printf "  %2s  line %-5s WAIT  %ss, as the lab tells the reader to\n" "$n" "$start" "$wait_for"
    sleep "$wait_for"
  fi
  printf "  %2s  line %-5s RUN   %s\n" "$n" "$start" "$first"
  ran=$((ran + 1))
  ( cd "$ROOT" && bash -eo pipefail "$file" ) > "$WORK/out-$n.log" 2>&1
  status=$?
  if [ "$status" -eq 0 ]; then
    printf "      ok\n"
  elif [ -n "$nonzero_ok" ]; then
    printf "      ok (non-zero exit %s, expected)\n" "$status"
  else
    printf "      FAILED (exit %s), last lines:\n" "$status"
    tail -5 "$WORK/out-$n.log" | cut -c1-160 | sed 's/^/      | /'
    failed=$((failed + 1))
    break
  fi
done < "$WORK/manifest"

echo
if [ "$MODE" != "--run" ]; then
  echo "re-run with --run to execute them"
  exit 0
fi
if [ "$failed" -gt 0 ]; then
  echo "a shipped command failed: fix the lab, not the report"
  exit 1
fi
if [ "$ran" -eq 0 ]; then
  echo "nothing was executed: every block is skipped or guarded."
  echo "This lab is verified by hand, not by this tool. Say so in the PR."
  exit 0
fi
echo "$ran of $total blocks executed, all exited 0"
