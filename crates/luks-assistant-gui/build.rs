fn main() {
    // Qt builds use Slint's native Qt style (KDE look); others use Fluent.
    let style = if std::env::var("CARGO_FEATURE_QT").is_ok() {
        "qt"
    } else {
        "fluent"
    };
    let style = std::env::var("LUKS_ASSISTANT_SLINT_STYLE").unwrap_or_else(|_| style.to_owned());
    let config = slint_build::CompilerConfiguration::new().with_style(style);
    slint_build::compile_with_config("ui/app.slint", config).expect("compile ui/app.slint");
    println!("cargo:rerun-if-env-changed=LUKS_ASSISTANT_SLINT_STYLE");
}
