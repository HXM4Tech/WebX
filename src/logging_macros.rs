macro_rules! now {
    () => {
        chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S UTC%:z")
            .to_string()
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => ({
        use colored::Colorize;
        eprintln!("{} {} {}", now!().dimmed(), "[INFO]".cyan().bold(), format!($($arg)*).cyan());
    })
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => ({
        use colored::Colorize;
        eprintln!("{} {} {}", now!().dimmed(), "[WARN]".yellow().bold(), format!($($arg)*).yellow());
    })
}

#[macro_export]
macro_rules! log_ok {
    ($($arg:tt)*) => ({
        use colored::Colorize;
        eprintln!("{} {} {}", now!().dimmed(), "[ OK ]".green().bold(), format!($($arg)*).green());
    })
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => ({
        use colored::Colorize;
        eprintln!("{} {} {}", now!().dimmed(), "[ERROR]".red().bold(), format!($($arg)*).red());
    })
}
