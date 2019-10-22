fn main() {
    match fullverif::main_wrap2() {
        Ok(_) => {}
        Err(err) => {
            println!("{}", err);
        }
    }
}
