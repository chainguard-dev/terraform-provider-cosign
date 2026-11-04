#!/bin/sh

# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

ready() {
  kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml --request-timeout=5s get --raw=/readyz &&
    kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml --request-timeout=5s wait --for=condition=Ready node --all --timeout=1s &&
    kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml --request-timeout=5s get serviceaccount/default -n default &&
    kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml --request-timeout=5s rollout status deployment/coredns -n kube-system --timeout=1s &&
    kubectl --kubeconfig=/etc/rancher/k3s/k3s.yaml --request-timeout=5s rollout status deployment/local-path-provisioner -n kube-system --timeout=1s
}
# Fulcio's chart trusts service account tokens from the issuer
# https://kubernetes.default.svc (k3s's default ends in .cluster.local), and
# fetches the issuer's keys only from the issuer's own host (the keys URL
# defaults to the node's address).
k3s server --disable=traefik,metrics-server --write-kubeconfig-mode=600 \
  --kube-apiserver-arg=service-account-issuer=https://kubernetes.default.svc \
  --kube-apiserver-arg=service-account-jwks-uri=https://kubernetes.default.svc/openid/v1/jwks \
  --data-dir=/var/lib/chainguard-microvm/k3s &
daemon=$!
trap 'kill "$daemon" 2>/dev/null || true' EXIT
trap 'exit 1' HUP INT TERM
until ready >/dev/null 2>&1; do
  kill -0 "$daemon" 2>/dev/null || exit 1
  sleep 0.1
done
printf '\n::service-ready::\n'
# With set -e, a nonzero daemon exit becomes the wrapper's exit status.
wait "$daemon"
# Even a clean daemon exit is unexpected while the job still needs it.
exit 1
