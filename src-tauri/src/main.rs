// Release builds are GUI apps: no console window, including when started in the background.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    nuvori_lib::run();
}
