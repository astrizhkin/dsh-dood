# Go build -> static scratch image (~3 MB, stdlib only).
# Deploy with docker compose (see ../docker-compose.yaml); the policy suite
# runs via:  docker compose run --rm guard-test
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /docker-guard .

FROM scratch AS runtime
COPY --from=build /docker-guard /docker-guard
COPY guard.json /app/guard.json
ENV GUARD_CONFIG=/app/guard.json
ENTRYPOINT ["/docker-guard"]

# Policy suite: node provides the fake daemon; curl + bash run the assertions
# against the compiled binary. Everything under /app; the fake bind-root
# fixture is /app/ws (GUARD_TEST_ROOT). The guard itself has no opinion about
# where the real workspace lives — that comes from GUARD_ALLOWED_BIND_ROOTS.
FROM node:22-alpine AS test
RUN apk add --no-cache curl bash
COPY --from=build /docker-guard /app/docker-guard
COPY policy-test.sh /app/policy-test.sh
ENV GUARD_TEST_ROOT=/app/ws
CMD ["bash", "/app/policy-test.sh"]
