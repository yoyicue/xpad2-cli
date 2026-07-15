mod apk;
mod catalog;
mod device;
mod embedded;
mod error;
mod install;
mod logging;
mod model;
mod ota;
mod root;
mod transaction;
mod util;

use crate::catalog::Catalog;
use crate::error::{Error, Result, msg};
use crate::logging::TransactionLog;
use crate::model::{ComponentState, Receipt};
use crate::util::{OperationLock, Paths, boot_id, output_text, run, selinux};
use serde_json::json;
use std::path::{Path, PathBuf};

fn main() {
    match run_main() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("xpad2: {error}");
            std::process::exit(if error.requires_reboot() { 75 } else { 1 });
        }
    }
}

fn run_main() -> Result<()> {
    let (args, cache_override) = parse_global_options(std::env::args().skip(1).collect())?;
    let paths = Paths::new(cache_override.as_deref());
    let catalog = Catalog::load()?;
    let Some(command) = args.first().map(String::as_str) else {
        print_help();
        return Ok(());
    };
    match command {
        "help" | "-h" | "--help" => print_help(),
        "version" | "--version" | "-V" => {
            println!(
                "xpad2 {} (catalog {})",
                env!("CARGO_PKG_VERSION"),
                catalog.lock.catalog_version
            );
        }
        "status" => command_status(&catalog, &paths, &args[1..])?,
        "list" => command_list(&catalog),
        "info" => command_info(&catalog, &paths, &args[1..])?,
        "doctor" => command_doctor(&catalog, &paths)?,
        "verify" => command_verify(&catalog, &paths, &args[1..])?,
        "root" => command_root(&catalog, &paths, &args[1..])?,
        "freeze" => command_freeze(&catalog, &paths, &args[1..])?,
        "unfreeze" => command_unfreeze(&catalog, &paths, &args[1..])?,
        "install" => command_install(&catalog, &paths, &args[1..])?,
        "repair" => command_repair(&catalog, &paths, &args[1..])?,
        "cleanup" => command_cleanup(&paths)?,
        "logs" => command_logs(&paths, &args[1..])?,
        "cache" => command_cache(&catalog, &paths, &args[1..])?,
        other => return Err(msg(format!("unknown command: {other}; run `xpad2 help`"))),
    }
    Ok(())
}

fn parse_global_options(args: Vec<String>) -> Result<(Vec<String>, Option<PathBuf>)> {
    let mut clean = Vec::new();
    let mut cache = None;
    let mut index = 0;
    let mut passthrough = false;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            passthrough = true;
            clean.push(arg.clone());
        } else if !passthrough && arg == "--cache-dir" {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| msg("--cache-dir requires a directory"))?;
            cache = Some(PathBuf::from(value));
        } else if !passthrough {
            if let Some(value) = arg.strip_prefix("--cache-dir=") {
                if value.is_empty() {
                    return Err(msg("--cache-dir requires a directory"));
                }
                cache = Some(PathBuf::from(value));
            } else {
                clean.push(arg.clone());
            }
        } else {
            clean.push(arg.clone());
        }
        index += 1;
    }
    Ok((clean, cache))
}

fn command_status(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() > 1 || args.first().is_some_and(|arg| arg != "--json") {
        return Err(msg("usage: xpad2 status [--json]"));
    }
    let status = device::snapshot(catalog, paths);
    if args.first().is_some_and(|arg| arg == "--json") {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!(
            "xpad2 {}  /260支持={}  SELinux={}",
            status.product_version,
            yes_no(status.supported),
            status.selinux
        );
        println!("boot-id: {}", status.boot_id);
        render_component(&status.temporary_root);
        for component in &status.components {
            render_component(component);
        }
        for warning in &status.transaction_warnings {
            println!("TRANSACTION: {warning}");
        }
        if let Some(action) = &status.action_required {
            println!("ACTION: {action}");
        }
    }
    Ok(())
}

fn command_list(catalog: &Catalog) {
    println!("ota              policy   freeze /260 system OTA package for user 0");
    println!("ksu              runtime  KernelSU 32547 / UAPI 2 / current boot");
    for id in ["ksu-manager", "xpad-installer", "boominstaller"] {
        if let Ok(a) = catalog.artifact(id) {
            println!(
                "{:<16} {:<8} {}",
                a.id,
                format!("{:?}", a.kind).to_ascii_lowercase(),
                a.version
            );
        }
    }
    println!("full             bundle   ksu + ksu-manager + xpad-installer + boominstaller");
}

fn command_info(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() != 1 {
        return Err(msg("usage: xpad2 info COMPONENT"));
    }
    let id = &args[0];
    if id == "ota" {
        println!(
            "id: ota\nkind: policy\npackages: {}\nlifecycle: persistent until `xpad2 unfreeze ota`",
            ota::PACKAGES.join(", ")
        );
        render_component(&ota::status());
        return Ok(());
    }
    if id == "ksu" {
        println!(
            "id: ksu\nkind: runtime\nversion: 32547\nuapi: 2\nkmi: xpad2-4.19.191\nlifecycle: current-boot"
        );
        render_component(&device::ksu_status(paths));
        return Ok(());
    }
    let artifact = catalog.artifact(id)?;
    println!("{}", serde_json::to_string_pretty(artifact)?);
    let state = match artifact.kind {
        model::ArtifactKind::Cli => device::cli_status(artifact),
        model::ArtifactKind::Apk => device::apk_status(artifact),
        _ => return Ok(()),
    };
    render_component(&state);
    Ok(())
}

fn command_doctor(catalog: &Catalog, paths: &Paths) -> Result<()> {
    let snapshot = device::snapshot(catalog, paths);
    println!(
        "[{}] firmware /260",
        if snapshot.supported { "OK" } else { "FAIL" }
    );
    println!(
        "[{}] SELinux {}",
        if snapshot.selinux == "Enforcing" {
            "OK"
        } else {
            "WARN"
        },
        snapshot.selinux
    );
    println!("[INFO] 普通 APK 安装不会把 Root、simpleperf 授权或 KSU Manager 当作预检查条件");
    render_component(&snapshot.temporary_root);
    for component in &snapshot.components {
        render_component(component);
    }
    for warning in &snapshot.transaction_warnings {
        println!("[WARN] {warning}");
    }
    if paths.cache.join("catalog.json").exists() || paths.cache.join("catalog.sig").exists() {
        match catalog::verify_cache(paths, catalog) {
            Ok(ids) => println!("[OK] cache signature + {} blobs verified", ids.len()),
            Err(error) => println!("[FAIL] cache: {error}"),
        }
    } else {
        println!("[INFO] cache empty; locked embedded artifacts are available");
    }
    if !snapshot.supported {
        return Err(msg("device is not the exact supported /260 profile"));
    }
    if let Some(component) = snapshot
        .components
        .iter()
        .find(|component| component.state == ComponentState::NeedsReboot)
    {
        return Err(Error::NeedsReboot(
            component
                .detail
                .clone()
                .unwrap_or_else(|| component.id.clone()),
        ));
    }
    Ok(())
}

fn command_verify(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() > 1 {
        return Err(msg("usage: xpad2 verify [COMPONENT]"));
    }
    let snapshot = device::snapshot(catalog, paths);
    let selected: Vec<_> = if let Some(id) = args.first() {
        let state = device::component(&snapshot, id)
            .ok_or_else(|| msg(format!("unknown component: {id}")))?;
        vec![state]
    } else {
        std::iter::once(&snapshot.temporary_root)
            .chain(snapshot.components.iter())
            .collect()
    };
    let mut failed = Vec::new();
    for state in selected {
        render_component(state);
        let healthy = match state.id.as_str() {
            "temporary-root" => {
                matches!(state.state, ComponentState::Absent | ComponentState::Active)
            }
            "ksu" => state.state == ComponentState::Active,
            "ota" => state.state == ComponentState::Active,
            "boominstaller" => state.state == ComponentState::Active,
            _ => state.state == ComponentState::Installed,
        };
        if !healthy {
            failed.push(state.id.clone());
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(msg(format!("verification failed: {}", failed.join(", "))))
    }
}

fn command_root(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    let command = if args.is_empty() {
        None
    } else if args.first().is_some_and(|arg| arg == "--") {
        Some(root::command_from_argv(&args[1..])?)
    } else {
        return Err(msg("usage: xpad2 root [-- COMMAND ARG...]"));
    };
    paths.ensure()?;
    let _lock = OperationLock::acquire(&paths.lock)?;
    let mut log = TransactionLog::start(paths, "root")?;
    let started_boot = boot_id();
    let started_selinux = selinux();
    let session = root::RootSession::acquire(catalog, paths, &mut log, true)?;
    let mut error = None;
    if let Some(command) = command {
        let output = session.exec(&command)?;
        log.command_result("root-command", output.status == 0, &output.text)?;
        if output.status != 0 {
            error = Some(format!("root command exited with {}", output.status));
        }
    }
    let receipt = Receipt {
        transaction_id: log.id.clone(),
        operation: "root".to_string(),
        success: error.is_none(),
        started_boot_id: started_boot,
        ended_boot_id: boot_id(),
        started_selinux,
        ended_selinux: selinux(),
        components: vec!["ota".to_string(), "temporary-root".to_string()],
        error: error.clone(),
        needs_reboot: false,
    };
    log.write_receipt(paths, &receipt)?;
    println!(
        "临时 Root 已验证并保留在当前启动周期；SELinux 当前为 {}。执行 `/data/local/tmp/su`，完成后务必运行 `xpad2 cleanup` 或普通重启。",
        selinux()
    );
    if let Some(error) = error {
        return Err(msg(error));
    }
    Ok(())
}

fn command_freeze(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() != 1 || args[0] != "ota" {
        return Err(msg("usage: xpad2 freeze ota"));
    }
    simple_transaction(paths, "freeze ota", |log| {
        device::profile_check(catalog)?;
        let state = ota::freeze(log)?;
        render_component(&state);
        Ok(vec!["ota".to_string()])
    })
}

fn command_unfreeze(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() != 1 || args[0] != "ota" {
        return Err(msg("usage: xpad2 unfreeze ota"));
    }
    simple_transaction(paths, "unfreeze ota", |log| {
        device::profile_check(catalog)?;
        let state = ota::unfreeze(log)?;
        render_component(&state);
        Ok(vec!["ota".to_string()])
    })
}

fn command_install(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    let Some(first) = args.first().map(String::as_str) else {
        return Err(msg(
            "usage: xpad2 install COMPONENT... | cli FILE [--name NAME] | apk FILE",
        ));
    };
    match first {
        "cli" => install_arbitrary_cli(catalog, paths, &args[1..]),
        "apk" => install_arbitrary_apk(catalog, paths, &args[1..]),
        _ => transaction::install_components(catalog, paths, args),
    }
}

fn install_arbitrary_cli(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(msg("usage: xpad2 install cli FILE [--name NAME]"));
    }
    let source = PathBuf::from(&args[0]);
    let name = match args.get(1).map(String::as_str) {
        None => None,
        Some("--name") if args.len() == 3 => Some(args[2].as_str()),
        _ => return Err(msg("usage: xpad2 install cli FILE [--name NAME]")),
    };
    simple_transaction(paths, "install cli", |log| {
        device::profile_check(catalog)?;
        let target = install::install_arbitrary_cli(&source, name, log)?;
        println!("installed: {}", target.display());
        Ok(vec![target.display().to_string()])
    })
}

fn install_arbitrary_apk(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() != 1 {
        return Err(msg("usage: xpad2 install apk FILE"));
    }
    let source = PathBuf::from(&args[0]);
    simple_transaction(paths, "install apk", |log| {
        device::profile_check(catalog)?;
        install::install_locked_cli(catalog, paths, "xpad-installer", log)?;
        let identity = install::install_arbitrary_apk(&source, log)?;
        println!(
            "installed: {} versionCode={}",
            identity.package, identity.version_code
        );
        Ok(vec![identity.package])
    })
}

fn command_repair(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() != 1 || args[0] == "full" {
        return Err(msg("usage: xpad2 repair COMPONENT"));
    }
    transaction::install_components(catalog, paths, args)
}

fn command_cleanup(paths: &Paths) -> Result<()> {
    paths.ensure()?;
    let _lock = OperationLock::acquire(&paths.lock)?;
    let mut log = TransactionLog::start(paths, "cleanup")?;
    let started_boot = boot_id();
    let started_selinux = selinux();
    if device::root_status().state == ComponentState::Active {
        let session = root::RootSession {
            owned: true,
            started_boot_id: started_boot.clone(),
        };
        session.close(&mut log)?;
    }
    if Path::new("/data/local/tmp/xpad-install").exists()
        && let Ok(output) = run("/data/local/tmp/xpad-install", &["cleanup"])
    {
        log.command_result(
            "xpad-install cleanup",
            output.status.success(),
            &output_text(&output),
        )?;
    }
    install::cleanup_work(paths)?;
    for path in [
        "/data/local/tmp/ionstack_reroot_device",
        "/data/local/tmp/ionstack_perf_target",
        "/data/local/tmp/ionstack_preload.so",
        "/data/local/tmp/cve43499_chainwalk_probe_arm32",
        "/data/local/tmp/temp_su.sock",
    ] {
        let _ = util::remove_if_exists(Path::new(path));
    }
    let receipt = Receipt {
        transaction_id: log.id.clone(),
        operation: "cleanup".to_string(),
        success: true,
        started_boot_id: started_boot,
        ended_boot_id: boot_id(),
        started_selinux,
        ended_selinux: selinux(),
        components: vec![],
        error: None,
        needs_reboot: false,
    };
    log.write_receipt(paths, &receipt)?;
    println!("cleanup complete; artifact cache was preserved");
    Ok(())
}

fn command_logs(paths: &Paths, args: &[String]) -> Result<()> {
    if args.len() != 2 || args[0] != "export" {
        return Err(msg("usage: xpad2 logs export DIRECTORY"));
    }
    let output = logging::export_logs(paths, Path::new(&args[1]))?;
    println!("{}", output.display());
    Ok(())
}

fn command_cache(catalog: &Catalog, paths: &Paths, args: &[String]) -> Result<()> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(msg(
            "usage: xpad2 cache path|list|verify|import|prune|clear",
        ));
    };
    match command {
        "path" if args.len() == 1 => println!("{}", paths.cache.display()),
        "list" if args.len() == 1 => {
            if !paths.cache.join("catalog.json").exists() {
                println!("cache empty: {}", paths.cache.display());
            } else {
                for id in catalog::verify_cache(paths, catalog)? {
                    let a = catalog.artifact(&id)?;
                    println!("{} {} {}", a.id, a.version, a.sha256);
                }
            }
        }
        "verify" if args.len() == 1 => {
            let ids = catalog::verify_cache(paths, catalog)?;
            println!("verified signed catalog and {} cached blobs", ids.len());
        }
        "import" if args.len() == 2 => {
            let source = PathBuf::from(&args[1]);
            simple_transaction(paths, "cache import", |log| {
                let count = catalog::import_cache(&source, paths, catalog)?;
                log.event(
                    "cache",
                    "imported",
                    json!({"source": source, "blobs": count}),
                )?;
                println!("imported {count} blobs into {}", paths.cache.display());
                Ok(vec![])
            })?;
        }
        "prune" if args.len() == 1 => {
            simple_transaction(paths, "cache prune", |log| {
                let count = catalog::prune_cache(paths, catalog)?;
                log.event("cache", "pruned", json!({"removed": count}))?;
                println!("removed {count} unlocked blobs");
                Ok(vec![])
            })?;
        }
        "clear" if args.len() == 1 => {
            simple_transaction(paths, "cache clear", |log| {
                let count = catalog::clear_cache(paths)?;
                log.event("cache", "cleared", json!({"removed": count}))?;
                println!("removed {count} cache files; embedded baseline remains available");
                Ok(vec![])
            })?;
        }
        _ => {
            return Err(msg(
                "usage: xpad2 cache path|list|verify|import DIRECTORY|prune|clear",
            ));
        }
    }
    Ok(())
}

fn simple_transaction<F>(paths: &Paths, operation: &str, action: F) -> Result<()>
where
    F: FnOnce(&mut TransactionLog) -> Result<Vec<String>>,
{
    paths.ensure()?;
    let _lock = OperationLock::acquire(&paths.lock)?;
    let mut log = TransactionLog::start(paths, operation)?;
    let started_boot = boot_id();
    let started_selinux = selinux();
    let result = action(&mut log);
    let (components, error, needs_reboot) = match &result {
        Ok(components) => (components.clone(), None, false),
        Err(error) => (vec![], Some(error.to_string()), error.requires_reboot()),
    };
    let receipt = Receipt {
        transaction_id: log.id.clone(),
        operation: operation.to_string(),
        success: result.is_ok(),
        started_boot_id: started_boot,
        ended_boot_id: boot_id(),
        started_selinux,
        ended_selinux: selinux(),
        components,
        error,
        needs_reboot,
    };
    log.write_receipt(paths, &receipt)?;
    result.map(|_| ())
}

fn render_component(component: &model::ComponentStatus) {
    println!(
        "{:<16} {:<13} {}",
        component.id,
        component.state,
        component.detail.as_deref().unwrap_or("")
    );
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn print_help() {
    println!(
        "xpad2 {} - XPad2 /260 root-capable offline installer\n\n\
Usage:\n  xpad2 status [--json]\n  xpad2 doctor\n  xpad2 list | info COMPONENT\n  xpad2 root [-- COMMAND ARG...]\n  xpad2 freeze ota | unfreeze ota\n  xpad2 install COMPONENT...\n  xpad2 install cli FILE [--name NAME]\n  xpad2 install apk FILE\n  xpad2 verify [COMPONENT]\n  xpad2 repair COMPONENT\n  xpad2 cleanup\n  xpad2 logs export DIRECTORY\n  xpad2 cache path|list|verify|import DIRECTORY|prune|clear\n\n\
Built-ins: ota, ksu, ksu-manager, xpad-installer, boominstaller, full\n\
Global: --cache-dir DIRECTORY (or XPAD2_CACHE_DIR)\n\n\
Exit 75 means an ordinary reboot is required.",
        env!("CARGO_PKG_VERSION")
    );
}
