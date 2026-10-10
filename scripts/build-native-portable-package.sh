#!/usr/bin/env bash
set -euo pipefail
if [[ ($# != 2 && $# != 3) || -z $1 || -z $2 ]]; then
  echo 'usage: build-native-portable-package.sh OUTPUT_DIRECTORY RELEASE_TAG [retained-full|auth-mocks]' >&2
  exit 2
fi
root=$(git rev-parse --show-toplevel)
cd "$root"
[[ -z $(git status --porcelain) ]] || { echo 'Package requires a clean immutable source checkout' >&2; exit 2; }
source=$(git rev-parse HEAD)
output=$(realpath -m "$1")
tag=$2
scope=${3:-retained-full}
case "$scope" in
  retained-full|auth-mocks) ;;
  *) echo 'Unknown verification scope; use retained-full or auth-mocks' >&2; exit 2 ;;
esac
mkdir -p "$output/test-receipts"
export CARGO_BUILD_JOBS=2
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
{
  printf 'source=%s\n' "$source"
  rustc --version
  cargo --version
  uv tool list
  pnpm --version
} > "$output/toolchain.txt"
printf '%s\n' "$source" > "$output/test-receipts/source-sha"
printf '%s\n' "$scope" > "$output/test-receipts/scope.log"
if [[ $scope == retained-full ]]; then
  pnpm install --filter agent-browser --frozen-lockfile --ignore-scripts
  cargo test --locked --manifest-path cli/Cargo.toml -- --test-threads=1 2>&1 | tee "$output/test-receipts/unit.log"
  for test in e2e_fill_controlled_ e2e_sensitive e2e_tab_state e2e_eval_runs_inside_the_active_frame e2e_console_includes_cross_origin_frame_logs e2e_attach_preserves_existing_cross_origin_frames; do
    cargo test --locked --manifest-path cli/Cargo.toml "$test" -- --ignored --test-threads=1 --nocapture 2>&1 | tee "$output/test-receipts/$test.log"
  done
  cargo zigbuild --locked --manifest-path cli/Cargo.toml --profile ci --target x86_64-unknown-linux-gnu.2.35
else
  cargo zigbuild --locked --manifest-path cli/Cargo.toml --profile ci --target x86_64-unknown-linux-gnu.2.35 --tests --message-format json-render-diagnostics > "$output/cargo-artifacts.jsonl" 2> "$output/compile.log"
  binaries=$(python3 - "$output/cargo-artifacts.jsonl" <<'PY'
import json
from pathlib import Path
import sys
artifacts = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
for name in ['agent-browser', 'session_info_cli']:
    matches = {item['executable'] for item in artifacts if item.get('reason') == 'compiler-artifact' and item['target']['name'] == name and item['profile']['test'] and item.get('executable')}
    if len(matches) != 1:
        raise RuntimeError(f'Expected exactly one compiled test executable for {name}: {matches}')
    executable = Path(matches.pop())
    if not executable.is_file():
        raise RuntimeError(f'Missing compiled test executable: {executable}')
    print(executable)
PY
  )
  mapfile -t test_bins <<< "$binaries"
  [[ ${#test_bins[@]} == 2 ]]
  "${test_bins[0]}" --list | tee "$output/test-receipts/test-list.log"
  "${test_bins[1]}" --list | tee -a "$output/test-receipts/test-list.log"
  for test in \
    plugins::tests::plugin_timeout_retires_lock_holder_descendant \
    plugins::tests::plugin_cancellation_retires_lock_holder_descendant \
    plugins::tests::credential_invocation_advertises_remaining_budget \
    connection::tests::test_auth_transport_does_not_replay_lost_response \
    commands::tests::test_auth_login_total_budget \
    native::daemon::test_auth_disconnect_cancels_queued_request \
    mcp::tests::auth_login_tool_exposes_and_forwards_no_navigate \
    session_info_transport_failure_is_not_runtime_success; do
    grep -Fx "$test: test" "$output/test-receipts/test-list.log"
  done
  "${test_bins[0]}" plugins::tests:: --test-threads=1 2>&1 | tee "$output/test-receipts/plugins.log"
  "${test_bins[0]}" test_auth_ --test-threads=1 2>&1 | tee "$output/test-receipts/auth-ipc.log"
  "${test_bins[0]}" auth_login_tool_exposes_and_forwards_no_navigate --test-threads=1 2>&1 | tee "$output/test-receipts/mcp-auth.log"
  "${test_bins[1]}" --test-threads=1 2>&1 | tee "$output/test-receipts/session-info-cli.log"
fi
install -m 755 cli/target/x86_64-unknown-linux-gnu/ci/agent-browser bin/agent-browser-linux-x64
bin/agent-browser-linux-x64 --version
pnpm pack --pack-destination "$output"
package="$output/agent-browser-0.37.1.tgz"
(cd "$output" && sha256sum agent-browser-0.37.1.tgz > agent-browser-0.37.1.tgz.sha256)
node scripts/native-package-proof.mjs "$package" bin/agent-browser-linux-x64 "$source" "$tag" > "$output/native-package-proof.json"
cp "$output/native-package-proof.json" "$output/test-receipts/"
tar -C "$output" -czf "$output/auth-deadline-test-receipts.tgz" test-receipts
node -e 'console.log(require("node:fs").readFileSync(process.argv[1], "utf8"))' "$output/native-package-proof.json"
