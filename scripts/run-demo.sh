#!/usr/bin/env bash
# Starts HavenHub on a scratch database with short alarm delays, then runs the scripted device demo.
# Usage: scripts/run-demo.sh [demo|load] [extra simulator args...]
set -euo pipefail
cd "$(dirname "$0")/.."
MODE="${1:-demo}"; shift || true
PORT="${PORT:-5080}"
WORK="$(mktemp -d)"
dotnet build -c Release -v quiet -nologo >/dev/null
export ASPNETCORE_ENVIRONMENT=Development ASPNETCORE_URLS="http://127.0.0.1:${PORT}"
export HavenHub__DatabasePath="$WORK/havenhub.db" HavenHub__ExitDelaySeconds=2 HavenHub__EntryDelaySeconds=2
export Logging__LogLevel__Default=Warning
if [ "$MODE" = "load" ]; then
  # Benchmarks create many accounts from one IP: lift the abuse limits for this run only.
  export HavenHub__AuthRequestsPerMinute=100000 HavenHub__CommandsPerMinute=100000 HavenHub__PairRequestsPerMinute=100000
fi
dotnet src/HavenHub.Api/bin/Release/net8.0/HavenHub.Api.dll --contentRoot "$PWD/src/HavenHub.Api" >"$WORK/api.log" 2>&1 &
API_PID=$!
trap 'kill $API_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null && break; sleep 0.2; done
curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null || { echo "API failed to start:"; cat "$WORK/api.log"; exit 1; }
dotnet tools/HavenHub.DeviceSim/bin/Release/net8.0/HavenHub.DeviceSim.dll "$MODE" --url "http://127.0.0.1:${PORT}" "$@"
