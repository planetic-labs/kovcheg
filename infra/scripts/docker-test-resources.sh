#!/bin/sh

set -eu

project_label='io.kovcheg.test.project'
purpose_label='io.kovcheg.test.purpose'
run_label='io.kovcheg.test.run-id'
source_label='io.kovcheg.test.source-sha'

print_owned() {
  kind=$1
  shift
  echo "PROJECT_OWNED $kind"
  "$@" --filter "label=$project_label=kovcheg"
}

echo 'Read-only Docker test resource report. No resources are removed.'
print_owned containers docker ps --all --format '{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Label "io.kovcheg.test.purpose"}}\t{{.Label "io.kovcheg.test.run-id"}}\t{{.Label "io.kovcheg.test.source-sha"}}'
print_owned images docker image ls --format '{{.ID}}\t{{.Repository}}:{{.Tag}}'
print_owned networks docker network ls --format '{{.ID}}\t{{.Name}}\t{{.Label "io.kovcheg.test.purpose"}}\t{{.Label "io.kovcheg.test.run-id"}}\t{{.Label "io.kovcheg.test.source-sha"}}'
print_owned volumes docker volume ls --format '{{.Name}}\t{{.Label "io.kovcheg.test.purpose"}}\t{{.Label "io.kovcheg.test.run-id"}}\t{{.Label "io.kovcheg.test.source-sha"}}'

echo 'UNDETERMINED legacy-name matches without complete ownership labels'
docker ps --all --format '{{.ID}}\t{{.Names}}' |
  awk '$2 ~ /^kovcheg-(smoke|realtime|db|deployment-smoke)-/ { print "container\t" $0 }'
docker image ls --format '{{.ID}}\t{{.Repository}}:{{.Tag}}' |
  awk '$2 ~ /^kovcheg-(smoke|realtime|db|deployment-smoke)-/ { print }' |
  while IFS="$(printf '\t')" read -r image_id image_ref; do
    image_project=$(docker image inspect --format '{{index .Config.Labels "io.kovcheg.test.project"}}' "$image_ref")
    image_purpose=$(docker image inspect --format '{{index .Config.Labels "io.kovcheg.test.purpose"}}' "$image_ref")
    image_run=$(docker image inspect --format '{{index .Config.Labels "io.kovcheg.test.run-id"}}' "$image_ref")
    image_source=$(docker image inspect --format '{{index .Config.Labels "io.kovcheg.test.source-sha"}}' "$image_ref")
    if [ "$image_project" != 'kovcheg' ] || [ "$image_purpose" = '<no value>' ] || \
      [ "$image_run" = '<no value>' ] || [ "$image_source" = '<no value>' ]; then
      printf 'image\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$image_id" "$image_ref" "$image_project" "$image_purpose" "$image_run" "$image_source"
    fi
  done
docker network ls --format '{{.ID}}\t{{.Name}}\t{{.Label "io.kovcheg.test.project"}}\t{{.Label "io.kovcheg.test.purpose"}}\t{{.Label "io.kovcheg.test.run-id"}}\t{{.Label "io.kovcheg.test.source-sha"}}' |
  awk '$2 ~ /^kovcheg-(smoke|realtime|db|deployment-smoke)-/ && ($3 != "kovcheg" || $4 == "" || $5 == "" || $6 == "") { print "network\t" $0 }'
docker volume ls --format '{{.Name}}\t{{.Label "io.kovcheg.test.project"}}\t{{.Label "io.kovcheg.test.purpose"}}\t{{.Label "io.kovcheg.test.run-id"}}\t{{.Label "io.kovcheg.test.source-sha"}}' |
  awk '$1 ~ /^kovcheg-(smoke|realtime|db|deployment-smoke)-/ && ($2 != "kovcheg" || $3 == "" || $4 == "" || $5 == "") { print "volume\t" $0 }'

echo "Ownership requires all four labels: $project_label, $purpose_label, $run_label, $source_label."
