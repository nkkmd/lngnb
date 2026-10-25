use std::process::Command;

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lngnb"))
        .args(args)
        .output()
        .expect("CLIを実行できること")
}

// R01: 新規取得環境でも実行する、工程②のプロセス境界試験。
#[test]
fn help_and_version_describe_development_status() {
    let help = cli(&["--help"]);
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    assert!(String::from_utf8(help.stdout).unwrap().contains("未実装"));
    let version = cli(&["--version"]);
    assert!(version.status.success());
    let text = String::from_utf8(version.stdout).unwrap();
    assert!(text.contains(env!("CARGO_PKG_VERSION")));
    assert!(text.contains("製品適合試験未完了"));
}

#[test]
fn unimplemented_and_malformed_operations_fail_without_success_output() {
    for args in [
        vec![],
        vec!["init"],
        vec!["serve"],
        vec!["publish"],
        vec!["pull"],
        vec!["backup"],
        vec!["restore"],
        vec!["unknown"],
        vec!["--version", "extra"],
        vec!["config", "show", "--data-dir"],
    ] {
        let result = cli(&args);
        assert_eq!(result.status.code(), Some(2), "{args:?}");
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8(result.stderr).unwrap().contains("エラー"));
    }
}

#[test]
fn config_preview_does_not_initialize_or_read_the_selected_path() {
    // ファイルである実行ファイル自身を渡す。設定読込み/ディレクトリ作成なら失敗する。
    let exe = env!("CARGO_BIN_EXE_lngnb");
    let before = std::fs::read(exe).unwrap();
    let result = cli(&["config", "show", "--data-dir", exe]);
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains("未保存・未適用"));
    assert!(text.contains("loopback"));
    assert!(text.contains("Restricted"));
    assert_eq!(std::fs::read(exe).unwrap(), before);
}
