#!/bin/bash
# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
#
# The redpanda-init service (pipeline/docker-compose.yml): runs once per 'up' and exits.
#   1. Write caching off (a cluster made by a 1.0 stack, in dev-container mode, had it on).
#   2. Three SASL/SCRAM-SHA-256 users, created or given their current password:
#        prohori-admin     superuser: only this script uses it
#        prohori-stage     the stage containers: every Prohori topic, the prohori-* groups
#        prohori-producer  replay, tail and Airflow's jobs: create and describe the topics,
#                          write raw-logs and dead-letter; it cannot read or join a group
#   3. SASL on for the Kafka API. The admin API (port 9644) is not published and stays
#      without a login on the stack's private network (ADR-0042).
# Safe to run again: users are updated, ACLs re-created (rpk ignores duplicates).
set -euo pipefail

export RPK_ADMIN_HOSTS=redpanda:9644
export RPK_BROKERS=redpanda:9092
TOPICS=(raw-logs events alerts incidents dead-letter)
MECHANISM=SCRAM-SHA-256

rpk cluster config set write_caching_default false

user() { # name password
  if rpk security user list | awk 'NR > 1 {print $1}' | grep -qx "$1"; then
    rpk security user update "$1" --new-password "$2" --mechanism "$MECHANISM" > /dev/null
  else
    rpk security user create "$1" --password "$2" --mechanism "$MECHANISM" > /dev/null
  fi
  echo "user $1 ready"
}
user prohori-admin "$KAFKA_ADMIN_PASSWORD"
user prohori-stage "$KAFKA_STAGE_PASSWORD"
user prohori-producer "$KAFKA_PRODUCER_PASSWORD"

rpk cluster config set superusers '["prohori-admin"]'
rpk cluster config set enable_sasl true

# From here on the Kafka API needs a login: the administrator's, from the environment.
export RPK_USER=prohori-admin RPK_PASS="$KAFKA_ADMIN_PASSWORD" RPK_SASL_MECHANISM="$MECHANISM"
acl() { rpk security acl create "$@" > /dev/null; }
for topic in "${TOPICS[@]}"; do
  acl --allow-principal User:prohori-stage --operation all --topic "$topic"
  acl --allow-principal User:prohori-producer --operation create,describe --topic "$topic"
done
acl --allow-principal User:prohori-producer --operation write --topic raw-logs
acl --allow-principal User:prohori-producer --operation write --topic dead-letter
acl --allow-principal User:prohori-stage --operation all --group prohori- \
  --resource-pattern-type prefixed
acl --allow-principal User:prohori-stage --allow-principal User:prohori-producer \
  --operation describe,idempotent_write --cluster
echo "SASL on; ACLs in place"
