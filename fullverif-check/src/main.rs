fn main() {
    match fullverif::main() {
        Ok(_) => {
            println!("Fullverif: finised successfully.");
        }
        Err(err) => {
            println!("{}", err);
        }
    }
}
