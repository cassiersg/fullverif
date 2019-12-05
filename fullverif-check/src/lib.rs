use crate::error::{CResult, CompError, CompErrorKind, CompErrors};
use crate::gadget_internals::GadgetInternals;
use crate::gadgets::Latency;
use crate::utils::format_set;

use std::collections::HashMap;
use std::fs::File;
use std::io::{prelude::*, BufReader};

use yosys_netlist_json as yosys;

#[macro_use]
extern crate log;
#[macro_use]
extern crate derivative;

mod clk_vcd;
mod comp_prop;
mod config;
mod error;
mod gadget_internals;
mod gadgets;
mod inner_affine;
mod netlist;
mod tg_graph;
mod utils;

// rnd_timings to map: port -> offsets for each cycle
fn abstract_rnd_timings<'a>(
    rnd_timings: impl Iterator<Item = &'a (gadgets::Random<'a>, Latency)>,
) -> Vec<HashMap<&'a str, Vec<usize>>> {
    let mut res = Vec::new();
    for (rnd, lat) in rnd_timings {
        if res.len() <= *lat as usize {
            res.resize(*lat as usize + 1, HashMap::new());
        }
        res[*lat as usize]
            .entry(rnd.port_name)
            .or_insert_with(Vec::new)
            .push(rnd.offset as usize);
    }
    res
}

/// Map the rnd_timings information to user-readable form.
fn rnd_timing_disp<'a>(
    rnd_timings: impl Iterator<Item = &'a (gadgets::Random<'a>, Latency)>,
) -> Vec<Vec<(&'a str, String)>> {
    abstract_rnd_timings(rnd_timings)
        .into_iter()
        .map(|t| {
            let mut res = t
                .into_iter()
                .map(|(rnd, offsets)| (rnd, crate::utils::format_set(offsets.into_iter())))
                .collect::<Vec<_>>();
            res.sort_unstable();
            res
        })
        .collect()
}

/// Verify that a gadgets satisfies all the rules
fn check_gadget<'a, 'b>(
    gadgets: &'b gadgets::Gadgets<'a>,
    gadget_name: gadgets::GKind<'a>,
    check_state_cleared: bool,
    check_rnd_annot: bool,
    controls: &mut clk_vcd::ModuleControls,
) -> CResult<'a, Option<tg_graph::AGadgetFlow<'a, 'b>>> {
    let gadget = &gadgets[&gadget_name];
    match gadget.strat {
        netlist::GadgetStrat::Assumed => Ok(None),
        netlist::GadgetStrat::Isolate => {
            println!("Checking gadget {}...", gadget_name);
            println!("Warning: latency annotations correctness is not verified under the 'isolate' strategy, only isolation is verified");
            if gadget.prop != netlist::GadgetProp::Affine {
                Err(CompError::ref_nw(
                    gadget.module,
                    CompErrorKind::Other(
                        "Invalid strategy 'isolate' for non-affine gadget".to_owned(),
                    ),
                ))?;
            }
            inner_affine::check_inner_affine(gadget)?;
            Ok(None)
        }
        netlist::GadgetStrat::CompositeProp => {
            println!("Checking gadget {}...", gadget_name);
            assert_eq!(gadget.strat, netlist::GadgetStrat::CompositeProp);
            println!("computing internals...");
            let gadget_internals = GadgetInternals::from_module(gadget, &gadgets)?;
            println!("internals computed");
            gadget_internals.check_sharings()?;
            println!("Sharings preserved: ok.");

            let n_cycles = controls.len() as gadgets::Latency;
            let max_delay_output = gadget.max_output_lat();
            if (max_delay_output + 1 > n_cycles) && !check_state_cleared {
                println!(
                    "Warning: not enough simulated cycles to simulate gadget {}.\nThis indicates \
                     that computation of this gadget is late with respect to the output shares.",
                    gadget_name
                );
                return Ok(None);
            }
            // This should have been checked before if check_state_cleared == true
            assert!(!(max_delay_output + 1 >= n_cycles && check_state_cleared));
            let n_cycles = std::cmp::min(n_cycles, max_delay_output + 2);
            println!("final n_cycles: {}", n_cycles);
            println!("Loaded simulation states.");
            println!("to graph...");
            let graph = tg_graph::BGadgetFlow::unroll(gadget_internals.clone(), n_cycles)?;
            let _a_graph = graph.annotate(controls)?;
            println!("annotation done");
            if false {
                _a_graph.disp_full();
            }
            println!("Valid gadgets:");
            for (g, c) in _a_graph.list_valid() {
                println!("\t{}: {}", g, format_set(c.into_iter()));
            }
            println!("Sensitive gadgets:");
            for (g, c) in _a_graph.list_sensitive() {
                println!("\t{}: {}", g, format_set(c.into_iter()));
            }
            _a_graph.check_valid_outputs()?;
            println!("Outputs valid: ok.");
            println!("Inputs exist.");
            for name in _a_graph.warn_useless_rnd() {
                println!("Warning: the gadget {:?} is not valid, although it has sensitive inputs and then requiring fresh randomness. If you didn't mean for it to be valid, consider muxing the inputs in order to make them non-sensitive when you don't use the gadget.", name);
            }
            let _rnd_times2 = _a_graph.randoms_input_timing(controls)?;
            println!("Randoms timed");
            println!("rnd_times:");
            for (i, times) in rnd_timing_disp(_rnd_times2.keys()).into_iter().enumerate() {
                println!("Cycle {}:", i);
                for (rnd, offsets) in times {
                    println!("\t{}: {}", rnd, offsets);
                }
            }
            if check_rnd_annot {
                _a_graph.check_randomness_usage(controls)?;
            }
            if check_state_cleared {
                _a_graph.check_state_cleared()?;
            }
            comp_prop::check_sec_prop(&_a_graph)?;
            println!("check successful for gadget {}", gadget_name);
            Ok(Some(_a_graph))
        }
    }
}

/// Verify that the top-level gadets (and all sub-gadgets) satisfy the rules.
fn check_gadget_top<'a>(
    netlist: &'a yosys::Netlist,
    simu: &mut impl Read,
    root_simu_mod: Vec<String>,
    gadget_name: &'a str,
    dut: String,
    clk: String,
    input_valid_signal: String,
    check_state_cleared: bool,
) -> Result<(), CompErrors<'a>> {
    let gadget_name = gadget_name.into();
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
    let max_delay_output = if let Some(g) = gadgets.get(&gadget_name) {
        g.max_output_lat()
    } else {
        return Err(CompError {
            module: None,
            net: None,
            kind: CompErrorKind::Other(format!(
                "Cannot find gadget {} in the netlist. Does it have the fv_prop annotation ?",
                gadget_name
            )),
        }
        .into());
    };
    if (max_delay_output + 1 > n_cycles)
        || (max_delay_output + 1 >= n_cycles && check_state_cleared)
    {
        return Err(CompError {
            module: Some(&netlist.modules[*gadget_name.get()]),
            net: None,
            kind: CompErrorKind::Other(format!(
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

    let g_graph = check_gadget(
        &gadgets,
        gadget_name,
        check_state_cleared,
        false,
        &mut controls,
    )?;
    let g_graph = if let Some(x) = g_graph {
        x
    } else {
        println!("Gadget is assumed to be correct");
        return Ok(());
    };

    let mut gadgets_to_check: Vec<(gadgets::GKind, _)> = Vec::new();
    // FIXME Should also check "only glitch" gadgets
    for ((name, cycle), base) in g_graph.sensitive_gadgets() {
        let gadget_name = base.kind.name;
        let controls = controls.submodule((*name.get()).to_owned(), cycle as usize);
        gadgets_to_check.push((gadget_name, controls));
    }
    let mut gadgets_checked: HashMap<gadgets::GKind, Vec<clk_vcd::StateLookups>> = HashMap::new();
    while let Some((sg_name, mut sg_controls)) = gadgets_to_check.pop() {
        let mut gadget_ok = false;
        for state_lookups in gadgets_checked.get(&sg_name).unwrap_or(&Vec::new()) {
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

        let ur_sg = check_gadget(
            &gadgets,
            sg_name,
            check_state_cleared,
            true,
            &mut sg_controls,
        )?;
        if let Some(ur_sg) = ur_sg {
            // Should also check "only glitch" gadgets
            for ((name, cycle), base) in ur_sg.sensitive_gadgets() {
                gadgets_to_check.push((
                    base.kind.name,
                    sg_controls.submodule((*name.get()).to_owned(), cycle as usize),
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

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    check_gadget_top(
        &netlist,
        &mut file_simu,
        root_simu_mod,
        config.gname.as_str(),
        config.dut.clone(),
        config.clk.clone(),
        config.in_valid.clone(),
        config.check_state_cleared,
    )
    .map_err(|e| format!("{}", e))?;
    Ok(())
}
