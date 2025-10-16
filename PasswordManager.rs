use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write, BufRead, BufReader};

extern crate crypto;
use crypto::digest::Digest;
use crypto::sha2::Sha256;

struct PasswordEntry {
    service: String,
    username: String,
    password: String,
}

struct PasswordManager {
    entries: HashMap<String, PasswordEntry>,
    master_password_hash: String,
    filename: String,
}

impl PasswordManager {
    fn new(filename: String) -> PasswordManager {
        PasswordManager {
            entries: HashMap::new(),
            master_password_hash: String::new(),
            filename,
        }
    }

    fn hash_password(password: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.input_str(password);
        hasher.result_str()
    }

    fn simple_encrypt(text: &str, key: &str) -> String {
        let key_bytes = key.as_bytes();
        let text_bytes = text.as_bytes();
        let mut result = String::new();

        for (i, byte) in text_bytes.iter().enumerate() {
            let key_byte = key_bytes[i % key_bytes.len()];
            let encrypted = byte ^ key_byte;
            result.push_str(&format!("{:02x}", encrypted));
        }

        result
    }

    fn simple_decrypt(encrypted: &str, key: &str) -> String {
        let key_bytes = key.as_bytes();
        let mut result = Vec::new();

        for i in (0..encrypted.len()).step_by(2) {
            if let Ok(byte) = u8::from_str_radix(&encrypted[i..i+2], 16) {
                let key_byte = key_bytes[(i/2) % key_bytes.len()];
                result.push(byte ^ key_byte);
            }
        }

        String::from_utf8_lossy(&result).to_string()
    }

    fn setup_master_password(&mut self, password: &str) {
        self.master_password_hash = Self::hash_password(password);
        self.save_master_hash();
    }

    fn verify_master_password(&self, password: &str) -> bool {
        Self::hash_password(password) == self.master_password_hash
    }

    fn save_master_hash(&self) {
        if let Ok(mut file) = File::create("master.hash") {
            writeln!(file, "{}", self.master_password_hash).ok();
        }
    }

    fn load_master_hash(&mut self) -> bool {
        if let Ok(file) = File::open("master.hash") {
            let reader = BufReader::new(file);
            if let Some(Ok(line)) = reader.lines().next() {
                self.master_password_hash = line;
                return true;
            }
        }
        false
    }

    fn add_entry(&mut self, service: String, username: String, password: String) {
        let entry = PasswordEntry {
            service: service.clone(),
            username,
            password,
        };
        self.entries.insert(service, entry);
        println!("Entry added successfully");
    }

    fn get_entry(&self, service: &str) -> Option<&PasswordEntry> {
        self.entries.get(service)
    }

    fn delete_entry(&mut self, service: &str) {
        if self.entries.remove(service).is_some() {
            println!("Entry deleted");
        } else {
            println!("Service not found");
        }
    }

    fn list_services(&self) {
        if self.entries.is_empty() {
            println!("No entries saved");
            return;
        }

        println!("\n=== Saved Services ===");
        for (service, entry) in &self.entries {
            println!("{} - {}", service, entry.username);
        }
    }

    fn save_to_file(&self, master_password: &str) {
        if let Ok(mut file) = File::create(&self.filename) {
            for (service, entry) in &self.entries {
                let encrypted_password = Self::simple_encrypt(&entry.password, master_password);
                writeln!(file, "{}|{}|{}", service, entry.username, encrypted_password).ok();
            }
            println!("Data saved");
        }
    }

    fn load_from_file(&mut self, master_password: &str) {
        if let Ok(file) = File::open(&self.filename) {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(line) = line {
                    let parts: Vec<&str> = line.split('|').collect();
                    if parts.len() == 3 {
                        let service = parts[0].to_string();
                        let username = parts[1].to_string();
                        let password = Self::simple_decrypt(parts[2], master_password);
                        
                        let entry = PasswordEntry {
                            service: service.clone(),
                            username,
                            password,
                        };
                        self.entries.insert(service, entry);
                    }
                }
            }
            println!("Data loaded");
        }
    }

    fn generate_password(length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        let mut rng = rand::thread_rng();
        
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
}

fn read_line() -> String {
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn read_password() -> String {
    print!("Enter password: ");
    io::stdout().flush().unwrap();
    read_line()
}

fn main() {
    let mut manager = PasswordManager::new("passwords.dat".to_string());
    
    let master_password = if manager.load_master_hash() {
        println!("Enter master password:");
        let password = read_password();
        if !manager.verify_master_password(&password) {
            println!("Invalid master password!");
            return;
        }
        manager.load_from_file(&password);
        password
    } else {
        println!("Setup new master password:");
        let password = read_password();
        manager.setup_master_password(&password);
        password
    };

    loop {
        println!("\n=== Password Manager ===");
        println!("1. Add Entry");
        println!("2. Get Entry");
        println!("3. Delete Entry");
        println!("4. List Services");
        println!("5. Generate Password");
        println!("6. Save and Exit");

        print!("\nEnter choice: ");
        io::stdout().flush().unwrap();
        let choice = read_line();

        match choice.as_str() {
            "1" => {
                print!("Service name: ");
                io::stdout().flush().unwrap();
                let service = read_line();
                
                print!("Username: ");
                io::stdout().flush().unwrap();
                let username = read_line();
                
                let password = read_password();
                
                manager.add_entry(service, username, password);
            }
            "2" => {
                print!("Service name: ");
                io::stdout().flush().unwrap();
                let service = read_line();
                
                if let Some(entry) = manager.get_entry(&service) {
                    println!("\nService: {}", entry.service);
                    println!("Username: {}", entry.username);
                    println!("Password: {}", entry.password);
                } else {
                    println!("Service not found");
                }
            }
            "3" => {
                print!("Service name: ");
                io::stdout().flush().unwrap();
                let service = read_line();
                manager.delete_entry(&service);
            }
            "4" => {
                manager.list_services();
            }
            "5" => {
                print!("Password length: ");
                io::stdout().flush().unwrap();
                let length = read_line().parse::<usize>().unwrap_or(16);
                let password = PasswordManager::generate_password(length);
                println!("Generated password: {}", password);
            }
            "6" => {
                manager.save_to_file(&master_password);
                break;
            }
            _ => {
                println!("Invalid choice");
            }
        }
    }
}
