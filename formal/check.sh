#!/usr/bin/env bash
# Runs the ProVerif models in parallel and compares each one's RESULT lines with the
# "Expected results" comment at its end. Usage: check.sh [model.pv ...], all models by default.
# PROVERIF overrides the proverif binary.
set -uo pipefail
cd "$(dirname "$0")"
proverif=${PROVERIF:-proverif}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

models=("$@")
[ ${#models[@]} -eq 0 ] && models=(*.pv)

for model in "${models[@]}"; do
  ( start=$SECONDS
    "$proverif" -lib nachalo "$model" > "$out/$model.log" 2>&1
    echo $((SECONDS - start)) > "$out/$model.time" ) &
done
wait

status=0
for model in "${models[@]}"; do
  expected=$(sed -n '/^(\* Expected results:$/,/^\*)$/p' "$model" | grep '^RESULT')
  actual=$(grep '^RESULT' "$out/$model.log")
  if [ -n "$expected" ] && [ "$actual" = "$expected" ]; then
    echo "ok    $model ($(cat "$out/$model.time")s)"
  else
    echo "FAIL  $model"
    diff <(echo "$expected") <(echo "$actual")
    grep -i 'error' "$out/$model.log"
    status=1
  fi
done
exit $status
