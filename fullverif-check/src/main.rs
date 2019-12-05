fn main() {
    match fullverif::main() {
        Ok(_) => {
            println!("Fullverif: finished successfully.");
        }
        Err(err) => {
            println!("{}", err);
        }
    }
}
