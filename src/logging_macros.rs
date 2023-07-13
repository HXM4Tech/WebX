#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => ({
        use colored::Colorize;
        eprintln!("{} {}", "[INFO]".cyan().bold(), format!($($arg)*).cyan());
    })
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => ({
        use colored::Colorize;
        eprintln!("{} {}", "[WARN]".yellow().bold(), format!($($arg)*).yellow());
    })
}

#[macro_export]
macro_rules! log_ok {
    ($($arg:tt)*) => ({
        use colored::Colorize;
        eprintln!("{} {}", "[ OK ]".green().bold(), format!($($arg)*).green());
    })
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => ({
        use colored::Colorize;
        eprintln!("{} {}", "[ERROR]".red().bold(), format!($($arg)*).red());
    })
}
