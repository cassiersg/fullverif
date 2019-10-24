#[macro_use]
extern crate derivative;
//use itertools::Itertools;
use crate::error::{CompError, CompErrorKind, CompErrors};
use std::collections::HashMap;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use yosys_netlist_json as yosys;
#[macro_use]
extern crate log;
#[cfg(feature = "flame_it")]
#[macro_use]
extern crate flamer;

mod clk_vcd;
mod config;
mod error;
mod gadget_internals;
mod gadgets;
mod netlist;
mod timed_gadgets;
mod utils;

#[cfg_attr(feature = "flame_it", flame)]
fn check_gadget<'a, 'b>(
    gadgets: &'b gadgets::Gadgets<'a>,
    gadget_name: gadgets::GKind<'a>,
    check_state_cleared: bool,
    controls: &mut clk_vcd::ModuleControls,
) -> Result<Option<timed_gadgets::UnrolledGadgetInternals<'a, 'b>>, CompErrors<'a>> {
    let gadget = &gadgets[gadget_name];
    if gadget.strat == netlist::GadgetStrat::Assumed {
        return Ok(None);
    }
    println!("Checking gadget {}...", gadget_name);
    assert_eq!(gadget.strat, netlist::GadgetStrat::CompositeProp);
    println!("computing internals...");
    let gadget_internals = gadget_internals::module2internals(gadget, &gadgets)?;
    println!("internals computed");
    gadget_internals::check_gadget_preserves_sharings(&gadgets, &gadget_internals)?;
    println!("Sharings preserved: ok.");

    let n_cycles = controls.len() as gadgets::Latency;
    let max_delay_output = gadget.max_output_lat();
    if (max_delay_output + 1 > n_cycles) && !check_state_cleared {
        println!(
            "Warning: not enough simulated cycles to simulate gadget {}.\nThis indicates that \
             computation of this gadget is late with respect to the output shares.",
            gadget_name
        );
        return Ok(None);
    }
    // This should have been checked before if check_state_cleared == true
    assert!(!(max_delay_output + 1 >= n_cycles && check_state_cleared));
    let n_cycles = std::cmp::min(n_cycles, max_delay_output + 2);
    println!("final n_cycles: {}", n_cycles);
    println!("Loaded simulation states.");
    let unrolled_gadget =
        timed_gadgets::unroll_gadget(gadget, gadget_internals, n_cycles, &gadget_name)?;
    println!("Unrolled gadget.");
    let unrolled_gadget = timed_gadgets::simplify_muxes(unrolled_gadget, controls)?;
    println!("Mux simplified.");
    let unrolled_gadget = timed_gadgets::do_not_compute_invalid(unrolled_gadget)?;
    println!("Removed invalid computations");
    println!("Gadgets:");
    for (g, c) in timed_gadgets::list_gadgets(&unrolled_gadget) {
        println!("\t{}: {}", g, c);
    }
    timed_gadgets::check_valid_outputs(&unrolled_gadget)?;
    println!("Outputs valid: ok.");
    // This is only a self-check, should never fail
    assert!(timed_gadgets::check_all_inputs_exist(&unrolled_gadget));
    println!("Inputs exist.");
    let rnd_times = timed_gadgets::randoms_input_timing(&unrolled_gadget, controls)?;
    println!("Randoms timed");
    println!("rnd_times:");
    for (i, times) in timed_gadgets::rnd_timing_disp(rnd_times.keys())
        .into_iter()
        .enumerate()
    {
        println!("Cycle {}:", i);
        for (rnd, offsets) in times {
            println!("\t{}: {}", rnd, offsets);
        }
    }
    if check_state_cleared {
        timed_gadgets::check_state_cleared(&unrolled_gadget, n_cycles)?;
    }
    timed_gadgets::check_sec_prop(&unrolled_gadget, gadget)?;
    println!("check successful for gadget {}", gadget_name);
    Ok(Some(unrolled_gadget))
}

#[cfg_attr(feature = "flame_it", flame)]
fn check_gadget2<'a>(
    netlist: &'a yosys::Netlist,
    simu: &mut impl Read,
    root_simu_mod: Vec<String>,
    gadget_name: &'a str,
    dut: String,
    clk: String,
    input_valid_signal: String,
    check_state_cleared: bool,
) -> Result<(), CompErrors<'a>> {
    let gadgets = gadgets::netlist2gadgets(netlist)?;
    println!("checking gadget {:?}", gadget_name);

    let mut clk_path = root_simu_mod.clone();
    clk_path.push(clk);
    let vcd_states = clk_vcd::VcdStates::new(simu, &clk_path)?;

    let mut cycle_count_path = root_simu_mod.clone();
    cycle_count_path.push("cycle_count".to_string());
    let _ = vcd_states.get_var_id(&cycle_count_path).map(|id| {
        for i in 0..vcd_states.len() {
            debug!("cycle_count[{}] = {:?}", i, vcd_states.get_var(id, i));
        }
    });

    let mut in_valid_path = root_simu_mod.clone();
    in_valid_path.push(input_valid_signal);

    let mut dut_path = root_simu_mod;
    dut_path.push(dut);
    let mut controls = clk_vcd::ModuleControls::from_enable(&vcd_states, dut_path, &in_valid_path)?;

    let n_cycles = controls.len() as gadgets::Latency;
    let max_delay_output = gadgets[gadget_name].max_output_lat();
    if (max_delay_output + 1 > n_cycles)
        || (max_delay_output + 1 >= n_cycles && check_state_cleared)
    {
        return Err(CompError {
            module: Some(netlist.modules[gadget_name].clone()),
            net: None,
            kind: CompErrorKind::Unknown(format!(
                "Not enough simulated cycles to check the top-level gadget.\n\
                 Note: number of simulated cycles should be at least maximum output delay{}.\n\
                 Note: max_out_delay: {}, n_cycles: {}.",
                if check_state_cleared {
                    " + 2 (since we are checking if state is cleared after last output)"
                } else {
                    " + 1"
                },
                max_delay_output,
                n_cycles
            )),
        }
        .into());
    }

    let unrolled_gadget = check_gadget(&gadgets, gadget_name, check_state_cleared, &mut controls)?;
    let unrolled_gadget = if let Some(x) = unrolled_gadget {
        x
    } else {
        println!("Gadget is assumed to be correct");
        return Ok(());
    };

    let mut gadgets_to_check: Vec<(&str, _)> = Vec::new();
    for ((name, cycle), tgi) in unrolled_gadget.subgadgets.iter() {
        let gadget_name = tgi.base.kind.name;
        let controls = controls.submodule((*name).to_owned(), *cycle as usize);
        gadgets_to_check.push((gadget_name, controls));
    }
    let mut gadgets_checked: HashMap<String, Vec<clk_vcd::StateLookups>> = HashMap::new();
    while let Some((sg_name, mut sg_controls)) = gadgets_to_check.pop() {
        let mut gadget_ok = false;
        for state_lookups in gadgets_checked.get(sg_name).unwrap_or(&Vec::new()) {
            if state_lookups.iter().all(|((path, cycle, idx), state)| {
                sg_controls.lookup(path.clone(), *cycle, *idx).unwrap() == state.as_ref()
            }) {
                gadget_ok = true;
                break;
            }
        }
        if gadget_ok {
            //println!("Gadget {} already checked, skipping.", sg_name);
            continue;
        }

        let ur_sg = check_gadget(&gadgets, sg_name, check_state_cleared, &mut sg_controls)?;
        if let Some(ur_sg) = ur_sg {
            for ((name, cycle), tgi) in ur_sg.subgadgets.iter() {
                gadgets_to_check.push((
                    tgi.base.kind.name,
                    sg_controls.submodule((*name).to_owned(), *cycle as usize),
                ));
            }
        }
        gadgets_checked
            .entry(sg_name.to_owned())
            .or_insert_with(Vec::new)
            .push(sg_controls.lookups());
    }
    Ok(())
}
pub fn main_wrap2() -> Result<(), Box<dyn std::error::Error>> {
    let config = config::parse_cmd_line();
    let file_synth = File::open(&config.json)
        .map_err(|_| format!("Did not find the result of synthesis '{}'.", &config.json))?;
    let file_synth = BufReader::new(file_synth);
    let file_simu = File::open(&config.vcd).map_err(|_| {
        format!(
            "Did not find the vcd file: '{}'.\nPlease check your testbench and simulator commands.",
            &config.vcd
        )
    })?;
    let mut file_simu = BufReader::new(file_simu);
    let netlist = yosys::Netlist::from_reader(file_synth)?;
    let root_simu_mod = vec![config.tb.clone()];
    match check_gadget2(
        &netlist,
        &mut file_simu,
        root_simu_mod,
        config.gname.as_str(),
        config.dut.clone(),
        config.clk.clone(),
        config.in_valid.clone(),
        config.check_state_cleared,
    ) {
        Ok(()) => {}
        Err(e) => {
            println!("{}", e);
        }
    };
    Ok(())
}
