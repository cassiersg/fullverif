#[cfg(feature = "flame_it")]
use std::fs::File;

#[cfg(feature = "flame_it")]
fn dump_flame() {
    flame::dump_html(&mut File::create("flame.html").unwrap()).unwrap();
}
#[cfg(not(feature = "flame_it"))]
fn dump_flame() {}

fn main() {
    match fullverif::main_wrap2() {
        Ok(_) => {
            println!("Fullverif: finised successfully.");
        }
        Err(err) => {
            println!("{}", err);
        }
    }
    dump_flame();
}
