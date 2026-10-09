#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 2 || -z $1 || -z $2 ]]; then
  echo 'usage: build-native-portable-package.sh OUTPUT_DIRECTORY RELEASE_TAG' >&2
  exit 2
fi
root=$(git rev-parse --show-toplevel)
cd "$root"
[[ -z $(git status --porcelain) ]] || { echo 'Package requires a clean immutable source checkout' >&2; exit 2; }
source=$(git rev-parse HEAD)
output=$(realpath -m "$1")
tag=$2
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
pnpm install --filter agent-browser --frozen-lockfile --ignore-scripts
cargo test --locked --manifest-path cli/Cargo.toml -- --test-threads=1 2>&1 | tee "$output/test-receipts/unit.log"
for test in e2e_fill_controlled_ e2e_sensitive e2e_tab_state e2e_eval_runs_inside_the_active_frame e2e_console_includes_cross_origin_frame_logs e2e_attach_preserves_existing_cross_origin_frames; do
  cargo test --locked --manifest-path cli/Cargo.toml "$test" -- --ignored --test-threads=1 --nocapture 2>&1 | tee "$output/test-receipts/$test.log"
done
cargo zigbuild --locked --manifest-path cli/Cargo.toml --profile ci --target x86_64-unknown-linux-gnu.2.35
install -m 755 cli/target/x86_64-unknown-linux-gnu/ci/agent-browser bin/agent-browser-linux-x64
bin/agent-browser-linux-x64 --version
pnpm pack --pack-destination "$output"
package="$output/agent-browser-0.37.1.tgz"
sha256sum "$package" > "$package.sha256"
node scripts/native-package-proof.mjs "$package" bin/agent-browser-linux-x64 "$source" "$tag" > "$output/native-package-proof.json"
node -e 'console.log(require("node:fs").readFileSync(process.argv[1], "utf8"))' "$output/native-package-proof.json"
