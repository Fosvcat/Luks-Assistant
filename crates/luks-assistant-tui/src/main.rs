fn main() {
    luks_assistant_tui::main_with_args(std::env::args().skip(1).collect());
}
