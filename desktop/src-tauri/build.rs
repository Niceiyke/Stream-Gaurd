// Tauri v2 build glue (spec 22 "Desktop Service"; engineering step 12).
// Generates the context/asset paths from `tauri.conf.json` so the app can
// call `tauri::generate_context!()`. Runs before the crate compiles.
fn main() {
    tauri_build::build()
}
