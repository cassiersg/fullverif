//! Command-line parsing for the app.

use clap::{App, Arg};

#[derive(Debug, Clone)]
pub struct Config {
    pub json: String,
    pub vcd: String,
    pub tb: String,
    pub gname: String,
    pub in_valid: String,
    pub dut: String,
    pub clk: String,
    pub check_state_cleared: bool,
    pub check_transitions: bool,
}

pub fn parse_cmd_line() -> Config {
    let matches = App::new("fullverif")
        .version("0.1")
        .author("Gaëtan Cassiers <gaetan.cassiers@uclouvain.be>")
        .about("Composition-based verification of masked hardware circuits.")
        .arg(
            Arg::with_name("json")
                .long("json")
                .value_name("FILE")
                .help("Synthesized json file from Yosys")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("vcd")
                .long("vcd")
                .value_name("FILE")
                .help("Simulation vcd file")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("tb")
                .long("tb")
                .help("Testbench module name")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("gname")
                .long("gname")
                .help("Main gadget module name")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("in_valid")
                .long("in-valid")
                .help("Name of the in_valid signal in the testbench")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("clock")
                .long("clock")
                .help("Name of the clock signal in the testbench")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("dut")
                .long("dut")
                .help("Name of the DUT module in the testbench")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("no_check_state_cleared")
                .long("no-check-cleared")
                .help("Skip verification that state is empty of valid sharings after last cycle.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("no_check_transitions")
                .long("no-check-transitions")
                .help("Skip verification that the circuit is transition-robust.")
                .takes_value(false),
        )
        .get_matches();
    let json = matches.value_of("json").unwrap().to_owned();
    let vcd = matches.value_of("vcd").unwrap().to_owned();
    let tb = matches.value_of("tb").unwrap().to_owned();
    let gname = matches.value_of("gname").unwrap().to_owned();
    let in_valid = matches.value_of("in_valid").unwrap().to_owned();
    let dut = matches.value_of("dut").unwrap().to_owned();
    let clk = matches.value_of("clock").unwrap().to_owned();
    let check_state_cleared = !matches.is_present("no_check_state_cleared");
    let check_transitions = !matches.is_present("no_check_transitions");
    Config {
        json,
        vcd,
        tb,
        gname,
        in_valid,
        dut,
        clk,
        check_state_cleared,
        check_transitions,
    }
}
