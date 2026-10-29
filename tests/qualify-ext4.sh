#!/usr/bin/env bash
# 自分で作った通常fileの96 MiBイメージだけをformat/mountする。実デバイスは指定しない。
set -euo pipefail
for command in mktemp truncate mkfs.ext4 mount umount mountpoint findmnt sudo cargo; do
  command -v "$command" >/dev/null
done
test "$(uname -s)" = Linux
root=$(mktemp -d "${RUNNER_TEMP:?}/lngnb-ext4.XXXXXX")
image="$root/disposable.img"
area="$root/mounted"
cleanup() {
  exit_code=$?
  trap - EXIT
  if mountpoint -q "$area"; then
    if ! sudo -n umount -- "$area"; then
      echo 'Disposable ext4 unmount failed; image retained' >&2
      exit 1
    fi
  fi
  rm -rf -- "$root" || exit_code=1
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -m 700 "$area"
truncate -s 96M "$image"
test -f "$image" && test ! -L "$image" && test "$(stat -c %s "$image")" = 100663296
mkfs.ext4 -q -F -m 0 "$image"
sudo -n mount -t ext4 -o loop,nodev,nosuid,noexec "$image" "$area"
sudo -n chown "$(id -u):$(id -g)" "$area"
chmod 700 "$area"
printf '%s\n' disposable-loop-ext4-v1 > "$area/.lngnb-disposable-ext4"
export LNGNB_FS_TESTING=disposable-loop-ext4-v1 LNGNB_EXT4_TEST_ROOT="$area" TMPDIR="$area"
findmnt --target "$area" --output SOURCE,FSTYPE,OPTIONS,SIZE
cargo test --locked --offline --lib storage::filesystem_tests:: -- --ignored --test-threads=1 --nocapture
# SQL拒否/FULLとprocess killはENOSPCと分けて、同じ隔離ext4上で再実行する。
cargo test --locked --offline --lib storage::tests:: -- --test-threads=1
cargo test --locked --offline --lib storage::blobs::tests::file_io_fault_points_never_create_durable_success -- --exact --test-threads=1
cargo test --locked --offline --lib storage::blobs::tests::process_kill_between_placement_and_database_commit -- --exact --test-threads=1

# 設定の原子的保存・SQL拒否・commit前後killも同じ隔離ext4で再実行する。
cargo test --locked --offline --lib storage::admin_config::tests:: -- --test-threads=1

# 停止中設定CLIの正常・拒否・保存/出力失敗も再実行する（通常件数へ二重加算しない）。
cargo test --locked --offline --test record_cli config_save_ -- --test-threads=1
