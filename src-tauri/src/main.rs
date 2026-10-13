// Hide the console window in release builds on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod model;
mod store;
mod totp;
mod util;

use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(commands::AppState::default())
        .setup(|app| {
            commands::spawn_auto_lock(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            // Lock on application close (drops keys, wipes the model, clears our clipboard value).
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                commands::lock_now(window.app_handle().state::<commands::AppState>().inner());
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::vault_create,
            commands::vault_unlock,
            commands::vault_lock,
            commands::change_password,
            commands::touch,
            commands::list_items,
            commands::export_accounts,
            commands::import_accounts,
            commands::search_items,
            commands::get_recovery_codes,
            commands::add_recovery_codes,
            commands::set_recovery_code_used,
            commands::delete_recovery_code,
            commands::get_item,
            commands::reveal_password,
            commands::save_item,
            commands::delete_item,
            commands::set_favorite,
            commands::totp_now,
            commands::copy_field,
            commands::generate_password,
            commands::get_settings,
            commands::set_settings,
            commands::list_folders,
            commands::create_folder,
            commands::rename_folder,
            commands::delete_folder,
            commands::list_files,
            commands::import_file,
            commands::export_file,
            commands::preview_file,
            commands::delete_file,
            commands::verify_vault,
        ])
        .run(tauri::generate_context!())
        .expect("error while running USNA Secure");
}
