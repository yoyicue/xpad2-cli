use crate::error::{Result, msg};
use crate::root::RootSession;
use crate::util::{output_text, run, shell_quote};

pub const KSUD: &str = "/data/adb/ksud";

pub fn dispatch_soft_reboot(root: &RootSession, log_path: &str) -> Result<()> {
    let command = format!("{} soft-reboot >{} 2>&1 &", KSUD, shell_quote(log_path));
    let output = root.exec(&command)?;
    if output.status != 0 {
        return Err(msg(format!(
            "cannot dispatch controlled userspace restart: {}",
            output.text
        )));
    }
    Ok(())
}

pub fn package_service_ready() -> bool {
    run("/system/bin/cmd", &["package", "path", "android"])
        .is_ok_and(|output| output.status.success() && output_text(&output).contains("package:"))
}
