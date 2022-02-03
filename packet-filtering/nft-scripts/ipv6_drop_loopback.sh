#!/bin/bash


evaluate() {
  echo "####################"
  echo "Running Command:  $1"
  echo "####################"
  eval $1
}


ADD_TABLE_CMD="nft add table ip6 filter"
ADD_COUNTER_CMD="nft add counter ip6 filter ctr"
ADD_CHAIN_CMD="nft add chain ip6 filter input \{type filter hook input priority 0\;\}"
ADD_RULE_CMD="nft add rule ip6 filter input ip6 daddr ::1 drop"

evaluate "$ADD_TABLE_CMD" &&
#evaluate "$ADD_COUNTER_CMD" &&
evaluate "$ADD_CHAIN_CMD" &&
evaluate "$ADD_RULE_CMD"

