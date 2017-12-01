#!/bin/sh

set -e

CGO_ENABLED=0 GOOS=linux ./build.sh

IMAGE=mumoshu/dd-zipkin-proxy-solo:v0.0.8

docker build --pull -t $IMAGE .
docker push $IMAGE
