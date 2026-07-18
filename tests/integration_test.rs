use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn apk_path(name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name);
    (p.exists() && is_valid_apk(&p)).then_some(p)
}

fn is_valid_apk(path: &Path) -> bool {
    use std::io::Read;
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }
    magic == [0x50, 0x4B, 0x03, 0x04]
}

fn binary_path() -> PathBuf {
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(profile)
        .join("apkhound")
}

#[test]
fn test_manifest_printed() {
    let apk = apk_path("co.kitetech.filemanager.apk");
    if apk.is_none() {
        eprintln!("skipping test_manifest_printed: APK not found");
        return;
    }
    let output = Command::new(binary_path())
        .arg("manifest")
        .arg(apk.unwrap())
        .arg("printed")
        .output()
        .expect("failed to run apkhound manifest");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ANDROID MANIFEST"));
    assert!(stdout.contains("co.kitetech.filemanager"));
}

#[test]
fn test_manifest_json() {
    let apk = apk_path("co.kitetech.filemanager.apk");
    if apk.is_none() {
        eprintln!("skipping test_manifest_json: APK not found");
        return;
    }
    let output = Command::new(binary_path())
        .arg("manifest")
        .arg(apk.unwrap())
        .arg("json")
        .output()
        .expect("failed to run apkhound manifest");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"package_name\""));
    assert!(stdout.contains("co.kitetech.filemanager"));
}

#[test]
fn test_permissions_single_apk() {
    let apk = apk_path("co.kitetech.filemanager.apk");
    if apk.is_none() {
        eprintln!("skipping test_permissions_single_apk: APK not found");
        return;
    }
    let output = Command::new(binary_path())
        .arg("permissions")
        .arg(apk.unwrap())
        .output()
        .expect("failed to run apkhound permissions");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("INTERNET"));
}

#[test]
fn test_permissions_diff() {
    let old = apk_path("co.kitetech.filemanager_old.apk");
    let new = apk_path("co.kitetech.filemanager.apk");
    if old.is_none() || new.is_none() {
        eprintln!("skipping test_permissions_diff: APK files not found");
        return;
    }
    let output = Command::new(binary_path())
        .arg("permissions")
        .arg(old.unwrap())
        .arg(new.unwrap())
        .output()
        .expect("failed to run apkhound permissions");
    assert!(output.status.success());
}

#[test]
fn test_compare() {
    let old = apk_path("co.kitetech.filemanager_old.apk");
    let new = apk_path("co.kitetech.filemanager.apk");
    if old.is_none() || new.is_none() {
        eprintln!("skipping test_compare: APK files not found");
        return;
    }
    let output = Command::new(binary_path())
        .arg("compare")
        .arg(old.unwrap())
        .arg(new.unwrap())
        .output()
        .expect("failed to run apkhound compare");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ADDED:") || stdout.contains("REMOVED:") || stdout.contains("CHANGED:")
    );
}

#[test]
fn test_compare_with_filter() {
    let old = apk_path("co.kitetech.filemanager_old.apk");
    let new = apk_path("co.kitetech.filemanager.apk");
    if old.is_none() || new.is_none() {
        eprintln!("skipping test_compare_with_filter: APK files not found");
        return;
    }
    let output = Command::new(binary_path())
        .arg("compare")
        .arg(old.unwrap())
        .arg(new.unwrap())
        .arg("-f")
        .arg("androidx")
        .output()
        .expect("failed to run apkhound compare with filter");
    assert!(output.status.success());
}

#[test]
fn test_match() {
    let old = apk_path("co.kitetech.filemanager_old.apk");
    let new = apk_path("co.kitetech.filemanager.apk");
    if old.is_none() || new.is_none() {
        eprintln!("skipping test_match: APK files not found");
        return;
    }
    let output = Command::new(binary_path())
        .arg("match")
        .arg(old.unwrap())
        .arg(new.unwrap())
        .arg("--threshold")
        .arg("0.5")
        .output()
        .expect("failed to run apkhound match");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Package (old)"));
    assert!(
        stdout.contains("MATCH")
            || stdout.contains("CHANGED")
            || stdout.contains("NEW")
            || stdout.contains("REMOVED")
    );
}

#[test]
fn test_match_csv() {
    let old = apk_path("co.kitetech.filemanager_old.apk");
    let new = apk_path("co.kitetech.filemanager.apk");
    if old.is_none() || new.is_none() {
        eprintln!("skipping test_match_csv: APK files not found");
        return;
    }
    let output = Command::new(binary_path())
        .arg("match")
        .arg(old.unwrap())
        .arg(new.unwrap())
        .arg("--csv")
        .output()
        .expect("failed to run apkhound match --csv");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("old_package,new_package,score,status"));
}

#[test]
fn test_callgraph() {
    let apk = apk_path("co.kitetech.filemanager.apk");
    if apk.is_none() {
        eprintln!("skipping test_callgraph: APK not found");
        return;
    }
    let output = Command::new(binary_path())
        .arg("callgraph")
        .arg(apk.unwrap())
        .arg("-f")
        .arg("androidx")
        .output()
        .expect("failed to run apkhound callgraph");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("digraph {"));
    assert!(stdout.contains("}"));
}

#[test]
fn test_extract() {
    let old = apk_path("co.kitetech.filemanager_old.apk");
    let new = apk_path("co.kitetech.filemanager.apk");
    if old.is_none() || new.is_none() {
        eprintln!("skipping test_extract: APK files not found");
        return;
    }
    let tmpdir = std::env::temp_dir().join("apkhound_extract_test");
    let _ = std::fs::remove_dir_all(&tmpdir);

    let output = Command::new(binary_path())
        .arg("extract")
        .arg(old.unwrap())
        .arg(new.unwrap())
        .arg(&tmpdir)
        .arg("-f")
        .arg("androidx")
        .output()
        .expect("failed to run apkhound extract");
    assert!(output.status.success());

    if tmpdir.exists() {
        let has_contents = std::fs::read_dir(&tmpdir)
            .map(|mut d| d.any(|e| e.is_ok()))
            .unwrap_or(false);
        if !has_contents {
            eprintln!("extract output dir is empty (may be valid if no changes match filter)");
        }
        let _ = std::fs::remove_dir_all(&tmpdir);
    }
}

#[test]
fn test_help() {
    let output = Command::new(binary_path())
        .arg("--help")
        .output()
        .expect("failed to run apkhound --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("callgraph"));
    assert!(stdout.contains("compare"));
    assert!(stdout.contains("manifest"));
    assert!(stdout.contains("permissions"));
    assert!(stdout.contains("match"));
    assert!(stdout.contains("extract"));
}
