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
mod raw_internals;
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
    check_rnd_annot: bool,
    controls: &mut clk_vcd::ModuleControls,
    config: &config::Config,
) -> CResult<'a, Option<tg_graph::GadgetFlow<'a, 'b>>> {
    let gadget = &gadgets[&gadget_name];
    match gadget.strat {
        netlist::GadgetStrat::Assumed => Ok(None),
        netlist::GadgetStrat::Isolate => {
            println!("Checking gadget {}...", gadget_name);
            if gadget.prop != netlist::GadgetProp::Affine {
                Err(CompError::ref_nw(
                    gadget.module,
                    CompErrorKind::Other(
                        "Invalid strategy 'isolate' for non-affine gadget".to_owned(),
                    ),
                ))?;
            }
            inner_affine::check_inner_affine(gadget)?;
            let gg = raw_internals::GadgetGates::from_gadget(gadget)?;
            let ugg = gg.unroll(controls)?;
            ugg.check_outputs_valid(ugg.annotate_valid())?;
            println!("outputs valid");
            if config.check_state_cleared {
                ugg.check_state_cleared(ugg.annotate_sensitive())?;
                println!("state cleared");
            }
            let _cg = ugg.computation_graph(ugg.annotate_sensitive());
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

            let n_simu_cycles = controls.len() as gadgets::Latency;
            let max_delay_output = gadget.max_output_lat();
            if config.check_state_cleared {
                assert!(max_delay_output + 1 < n_simu_cycles);
            } else if max_delay_output + 1 > n_simu_cycles {
                println!(
                    "Error: not enough simulated cycles to simulate gadget {}.\nThis indicates \
                     that computation of this gadget is late with respect to the output shares. \
                     Skipping verification of this gadget.",
                    gadget_name
                );
                return Ok(None);
            }
            let n_analysis_cycles = if config.check_state_cleared {
                max_delay_output + 2
            } else {
                max_delay_output + 1
            };
            println!(
                "Analyzing execution of the gadget over {} cycles (based on output latencies).",
                n_analysis_cycles
            );
            println!("Loaded simulation states.");
            println!("to graph...");
            let graph =
                tg_graph::GadgetFlow::new(gadget_internals.clone(), n_analysis_cycles, controls)?;
            if config.verbose {
                graph.disp_full();
            }
            println!("Valid gadgets:");
            let mut valid_gadgets: Vec<String> = graph
                .list_valid()
                .into_iter()
                .map(|(g, c)| format!("\t{}: {}", g, format_set(c.into_iter())))
                .collect();
            valid_gadgets.sort_unstable();
            for vg in valid_gadgets {
                println!("{}", vg);
            }
            println!("Sensitive gadgets:");
            for (g, c) in graph.list_sensitive(tg_graph::Sensitive::Yes) {
                println!("\t{}: {}", g, format_set(c.into_iter()));
            }
            println!("Glitch-sensitive gadgets:");
            for (g, c) in graph.list_sensitive(tg_graph::Sensitive::Glitch) {
                println!("\t{}: {}", g, format_set(c.into_iter()));
            }
            graph.check_valid_outputs()?;
            println!("Outputs valid: ok.");
            println!("Inputs exist.");
            for name in graph.warn_useless_rnd() {
                println!("Warning: the gadget {:?} does not perform valid computations, but it has sensitive inputs, hence requires randomness to not leak them. Consider muxing the sensitive inputs to avoid wasting randomness.", name);
            }
            let _rnd_times2 = graph.randoms_input_timing(controls)?;
            println!("Randoms timed");
            println!("rnd_times:");
            for (i, times) in rnd_timing_disp(_rnd_times2.keys()).into_iter().enumerate() {
                println!("Cycle {}:", i);
                for (rnd, offsets) in times {
                    println!("\t{}: {}", rnd, offsets);
                }
            }
            if check_rnd_annot {
                graph.check_randomness_usage(controls)?;
            }
            if config.check_state_cleared {
                graph.check_state_cleared()?;
            }
            if config.check_transitions {
                graph.check_parallel_seq_gadgets()?;
            }
            comp_prop::check_sec_prop(&graph)?;
            println!("check successful for gadget {}", gadget_name);
            Ok(Some(graph))
        }
    }
}

/// Verify that the top-level gadets (and all sub-gadgets) satisfy the rules.
fn check_gadget_top<'a>(
    netlist: &'a yosys::Netlist,
    simu: &mut impl Read,
    root_simu_mod: Vec<String>,
    config: &'a config::Config,
) -> Result<(), CompErrors<'a>> {
    let gadget_name = config.gname.as_ref();
    let gadgets = gadgets::netlist2gadgets(netlist)?;
    println!("checking gadget {:?}", gadget_name);

    let mut clk_path = root_simu_mod.clone();
    clk_path.push(config.clk.clone());
    let vcd_states = clk_vcd::VcdStates::new(simu, &clk_path)?;

    let mut cycle_count_path = root_simu_mod.clone();
    cycle_count_path.push("cycle_count".to_string());
    let _ = vcd_states.get_var_id(&cycle_count_path).map(|id| {
        for i in 0..vcd_states.len() {
            debug!("cycle_count[{}] = {:?}", i, vcd_states.get_var(id, i));
        }
    });

    let mut in_valid_path = root_simu_mod.clone();
    in_valid_path.push(config.in_valid.clone());

    let mut dut_path = root_simu_mod;
    dut_path.push(config.dut.clone());
    let mut controls = clk_vcd::ModuleControls::from_enable(&vcd_states, dut_path, &in_valid_path)?;

    let n_cycles = controls.len() as gadgets::Latency;
    let max_delay_output = if let Some(g) = gadgets.get(&gadgets::GKind::from(gadget_name)) {
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
        || (max_delay_output + 1 >= n_cycles && config.check_state_cleared)
    {
        return Err(CompError {
            module: Some(&netlist.modules[gadget_name]),
            net: None,
            kind: CompErrorKind::Other(format!(
                "Not enough simulated cycles to check the top-level gadget.\n\
                 Note: number of simulated cycles should be at least maximum output delay{}.\n\
                 Note: max_out_delay: {}, n_cycles: {}.",
                if config.check_state_cleared {
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
        gadgets::GKind::from(gadget_name),
        false,
        &mut controls,
        config,
    )?;
    let g_graph = if let Some(x) = g_graph {
        x
    } else {
        println!("Gadget is assumed to be correct");
        return Ok(());
    };

    let mut gadgets_to_check: Vec<(gadgets::GKind, _)> = Vec::new();
    // FIXME Should also check "only glitch" gadgets
    for ((name, cycle), base) in g_graph.sensitive_stable_gadgets() {
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

        let ur_sg = check_gadget(&gadgets, sg_name, true, &mut sg_controls, config)?;
        if let Some(ur_sg) = ur_sg {
            // FIXME Should also check "only glitch" gadgets
            for ((name, cycle), base) in ur_sg.sensitive_stable_gadgets() {
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
    check_gadget_top(&netlist, &mut file_simu, root_simu_mod, &config)
        .map_err(|e| format!("{}", e))?;
    Ok(())
}
