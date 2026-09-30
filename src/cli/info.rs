/// 运行版本信息
pub fn run_info(detailed: bool) {
    println!("DataChain v0.1.0");
    println!("Rust 语言重构版本");

    if detailed {
        println!();
        println!("Rust 版本: {}", rustc_version_runtime::version());
        println!("操作系统: {}", std::env::consts::OS);
        println!("架构: {}", std::env::consts::ARCH);
        println!("编译时间: {}", env!("CARGO_PKG_VERSION"));

        // 内存信息
        #[cfg(target_os = "linux")]
        {
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                for line in meminfo.lines().take(3) {
                    println!("{}", line);
                }
            }
        }
    }
}
