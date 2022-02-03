#!/bin/bash


evaluate() {
  echo "####################"
  echo "Running Command:  $1"
  echo "####################"
  eval $1
}

IPADDR="fdf2:5e8e:743d::2"


ADD_TABLE_CMD="nft add table ip6 filter"
ADD_CHAIN_CMD="nft add chain ip6 filter input \{type filter hook input priority 0\;\}"
ADD_RULE_CMD="nft add rule ip6 filter input ip6 saddr ${IPADDR} drop"
TEST_FILTER_CMD="wget http://[${IPADDR}]:80/testfile"

evaluate "$ADD_TABLE_CMD" &&
evaluate "$ADD_CHAIN_CMD" &&
evaluate "$ADD_RULE_CMD" &&
evaluate "$TEST_FILTER_CMD"

