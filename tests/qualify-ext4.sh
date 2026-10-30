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

# 保存設定の起動適用・破損拒否・手動待ち維持も再実行する。
cargo test --locked --offline --test record_cli saved_startup_ -- --test-threads=1

# 停止中保存設定の読取り・拒否・出力失敗を再実行する。
cargo test --locked --offline --test record_cli config_show_ -- --test-threads=1

# 起動Recordのbyte分割・一件未満の予算不足を再実行する。
cargo test --locked --offline --test record_cli startup_byte_budget_ -- --test-threads=1

# 起動Blobのbyte分割・予算不足・後続破損を再実行する。
cargo test --locked --offline --test record_cli startup_blob_byte_budget_ -- --test-threads=1

# 起動Blobの対象数分割・未保持対象の計上を再実行する。
cargo test --locked --offline --test record_cli startup_blob_target_budget_ -- --test-threads=1

# 起動時依存入力の辺数分割・一Revision未満の不足を再実行する。
cargo test --locked --offline --test record_cli startup_edge_budget_ -- --test-threads=1

# 起動時親評価の件数分割・次checkpoint保存失敗を再実行する。
cargo test --locked --offline --test record_cli startup_evaluation_budget_ -- --test-threads=1

# 保存sessionのSQL callback予算・起動前拒否/手動待ち維持を再実行する。
cargo test --locked --offline --test record_cli sql_callback_budget_ -- --test-threads=1

# SQL時間予算の起動/実受理・非保存・手動待ち維持も再実行する。
cargo test --locked --offline --test record_cli sql_time_budget_ -- --test-threads=1

# 起動局所/物理検査のstep時間指定・分割完了・非保存・手動待ち維持を再実行する。
cargo test --locked --offline --test record_cli startup_inspection_time_budget_ -- --test-threads=1

# 起動依存入力のstep時間指定・収集完了・非保存・手動待ち維持。
cargo test --locked --offline --test record_cli startup_record_input_time_budget_ -- --test-threads=1

# 本文評価入力のstep時間指定・分割完了・非保存・手動待ち維持。
cargo test --locked --offline --test record_cli startup_blob_input_time_budget_ -- --test-threads=1

# 親評価のstep期限不足/進捗保全とCLIの時間指定・非保存・手動待ち維持。
cargo test --locked --offline --lib storage::startup::tests::parent_evaluation_deadline_preserves_checkpoints_and_other_phases -- --exact --test-threads=1
cargo test --locked --offline --test record_cli startup_parent_time_budget_ -- --test-threads=1

# 設定共通保存と稼働中変更の内部基盤を同じext4で再実行する。
cargo test --locked --offline --lib storage::management::tests::checked_config_save_is_shared_without_applying_session_values_or_clearing_manual_wait -- --exact --test-threads=1
cargo test --locked --offline --lib storage::admin_transport::configuration::tests:: -- --test-threads=1

# 設定専用IPCの固定形式/保全/応答喪失とclientの非降格。
cargo test --locked --offline --lib storage::admin_transport::client::tests::config_client_never_falls_back_or_confirms_mismatched_and_lost_responses -- --exact --test-threads=1

# 稼働中設定変更CLI・前面受理側の保存/反映/異常時保全を再実行する。
cargo test --locked --offline --test record_cli config_change_ -- --test-threads=1

# 停止中設定保存の共通管理処理・保存/正常停止失敗時の保全。
cargo test --locked --offline --lib storage::management::tests::stopped_config_ -- --test-threads=1
