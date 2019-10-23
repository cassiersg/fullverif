use crate::clk_vcd;
use crate::error::{CompError, CompErrorKind, CompErrors};
use crate::gadget_internals::{self, Connection, GName, RndConnection};
use crate::gadgets::{self, Gadget, Gadgets, Latency, Sharing};
use crate::netlist;
use std::collections::{HashMap, HashSet};
use yosys_netlist_json as yosys;

pub type Name<'a> = (GName<'a>, Latency);
pub type TRandom<'a> = (RndConnection<'a>, Latency);
type TSharing<'a> = (Sharing<'a>, Latency);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TConnection<'a> {
    GadgetOutput {
        gadget_name: Name<'a>,
        output: Sharing<'a>,
    },
    Input(TSharing<'a>),
    Invalid(Option<Box<TConnection<'a>>>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TGadgetInstance<'a> {
    pub base: gadget_internals::GadgetInstance<'a>,
    pub input_connections: HashMap<Sharing<'a>, TConnection<'a>>,
    pub random_connections: HashMap<gadgets::Random<'a>, TRandom<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnrolledGadgetInternals<'a> {
    module: &'a yosys::Module,
    pub subgadgets: HashMap<Name<'a>, TGadgetInstance<'a>>,
    output_connections: HashMap<TSharing<'a>, TConnection<'a>>,
    inputs: HashSet<TSharing<'a>>,
    n_cycles: Latency,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Validity {
    Valid,
    Invalid,
    Any,
}

fn time_connection<'a>(
    conn: &Connection<'a>,
    gadgets: &Gadgets<'a>,
    internals: &gadget_internals::GadgetInternals<'a>,
    inputs: &HashSet<TSharing<'a>>,
    src_latency: Latency,
    cycle: Latency,
    time_range: std::ops::Range<Latency>,
) -> TConnection<'a> {
    match conn {
        Connection::GadgetOutput {
            gadget_name,
            output,
        } => {
            let output_latency = gadgets[internals.subgadgets[*gadget_name].kind].outputs[output];
            if let Some(ref_cycle) = (cycle + src_latency)
                .checked_sub(output_latency)
                .filter(|ref_cycle| time_range.contains(ref_cycle))
            {
                TConnection::GadgetOutput {
                    gadget_name: (gadget_name, ref_cycle),
                    output: *output,
                }
            } else {
                //TConnection::Invalid(Some(Box::new(out_connection)))
                TConnection::Invalid(None)
            }
        }
        Connection::Input(input) => {
            let tsharing = (*input, src_latency + cycle);
            if inputs.contains(&tsharing) {
                TConnection::Input(tsharing)
            } else {
                TConnection::Invalid(Some(Box::new(TConnection::Input(tsharing))))
            }
        }
    }
}

fn retime_connection<'a>(conn: &TConnection<'a>, cycle: Latency) -> TConnection<'a> {
    match conn {
        TConnection::GadgetOutput {
            gadget_name: (name, _),
            output,
        } => TConnection::GadgetOutput {
            gadget_name: (name, cycle),
            output: *output,
        },
        TConnection::Input((sharing, _)) => TConnection::Input((*sharing, cycle)),
        TConnection::Invalid(x) => TConnection::Invalid(x.clone()),
    }
}

fn time_random<'a>(
    random_name: &gadgets::Random<'a>,
    sgi: &gadget_internals::GadgetInstance<'a>,
    gadgets: &Gadgets<'a>,
    cycle: Latency,
) -> Result<TRandom<'a>, CompError<'a>> {
    let random_lat = &gadgets[sgi.kind].randoms[random_name].ok_or_else(|| {
        CompError::ref_sn(
            &gadgets[sgi.kind].module,
            &random_name.port_name,
            CompErrorKind::MissingAnnotation("psim_lat".to_owned()),
        )
    })?;
    let new_cycle = random_lat + cycle;
    Ok((sgi.random_connections[random_name], new_cycle))
}

pub fn unroll_gadget<'a>(
    gadget: &Gadget<'a>,
    internals: &gadget_internals::GadgetInternals<'a>,
    gadgets: &Gadgets<'a>,
    n_cycles: Latency,
    _gadget_name: &str,
) -> Result<UnrolledGadgetInternals<'a>, CompError<'a>> {
    debug!("unroll, n_cycles: {}", n_cycles);
    let inputs = gadget
        .inputs
        .iter()
        .map(|(input, lat)| (*input, *lat))
        .collect::<HashSet<_>>();
    let timed_subgadgets = internals
        .subgadgets
        .iter()
        .flat_map(|x| (0..n_cycles).map(move |c| (x, c)))
        .map(|((sg_name, sgi), cycle)| {
            let new_name = (*sg_name, cycle);
            let instance = TGadgetInstance {
                base: sgi.clone(),
                input_connections: sgi
                    .input_connections
                    .iter()
                    .map(|(c_name, conn)| {
                        let src_latency = gadgets[sgi.kind].inputs[c_name];
                        (
                            *c_name,
                            time_connection(
                                conn,
                                gadgets,
                                internals,
                                &inputs,
                                src_latency,
                                cycle,
                                0..n_cycles,
                            ),
                        )
                    })
                    .collect::<HashMap<_, _>>(),
                random_connections: sgi
                    .random_connections
                    .keys()
                    .map(|r_name| Ok((*r_name, time_random(r_name, sgi, gadgets, cycle)?)))
                    .collect::<Result<HashMap<_, _>, _>>()?,
            };
            Ok((new_name, instance))
        })
        .collect::<Result<HashMap<Name<'a>, TGadgetInstance<'a>>, CompError<'a>>>()?;
    let timed_outputs = internals
        .output_connections
        .iter()
        .flat_map(|x| (0..n_cycles).map(move |c| (x, c)))
        .map(|((output, conn), cycle)| {
            (
                (*output, cycle),
                time_connection(conn, gadgets, internals, &inputs, 0, cycle, 0..n_cycles),
            )
        })
        .collect::<HashMap<_, _>>();
    Ok(UnrolledGadgetInternals {
        module: gadget.module,
        subgadgets: timed_subgadgets,
        output_connections: timed_outputs,
        inputs,
        n_cycles,
    })
}

pub fn simplify_muxes<'a, 'b>(
    mut urgi: UnrolledGadgetInternals<'a>,
    controls: &mut clk_vcd::ModuleControls<'b>,
    gadgets: &Gadgets<'a>,
) -> Result<UnrolledGadgetInternals<'a>, CompError<'a>> {
    // Map connections from output of muxes to inputs
    let mut conn_mappings = HashMap::new();
    let mut muxes = Vec::new();
    for (sgi_name, sgi) in urgi.subgadgets.iter() {
        let sg = &gadgets[sgi.base.kind];
        if sg.prop == netlist::GadgetProp::Mux {
            muxes.push(sgi_name.clone());
            // FIXME parmeterize
            let sel_name = "sel".to_owned();
            //let sel_name = sg.controls.keys().next().unwrap().clone();
            let path: Vec<String> = vec![sgi_name.0.to_owned(), sel_name.to_owned()];
            let sel = controls
                .lookup(path, sgi_name.1 as usize, 0)?
                .unwrap_or_else(|| {
                    panic!(
                        "Missing simulation cycle for mux selector, gadget: {:?}",
                        sgi_name
                    )
                });
            let sel = match sel {
                clk_vcd::VarState::Scalar(vcd::Value::V0) => Some(false),
                clk_vcd::VarState::Scalar(vcd::Value::V1) => Some(true),
                clk_vcd::VarState::Vector(_) => unreachable!(),
                _ => None,
            };
            for output in gadgets[sgi.base.kind].outputs.keys() {
                let old_conn = TConnection::GadgetOutput {
                    gadget_name: *sgi_name,
                    output: *output,
                };
                let new_conn = match sel {
                    Some(sel_bool) => sgi.input_connections[&gadgets::Sharing {
                        port_name: if sel_bool { "in_true" } else { "in_false" },
                        pos: output.pos,
                    }]
                        .clone(),
                    None => TConnection::Invalid(None),
                };
                if old_conn == new_conn {
                    return Err(CompError::ref_nw(
                        &urgi.module,
                        CompErrorKind::Unknown(format!(
                            "Mux {:?} takes its output as input.",
                            sgi_name
                        )),
                    ));
                }
                conn_mappings.insert(old_conn, new_conn);
            }
        }
    }
    for mux in muxes {
        urgi.subgadgets.remove(&mux);
    }
    for conn in urgi
        .subgadgets
        .values_mut()
        .flat_map(|sgi| sgi.input_connections.values_mut())
        .chain(urgi.output_connections.values_mut())
    {
        let mut conn_stack = vec![&*conn];
        let mut curr_conn = &*conn;
        while let Some(new_conn) = conn_mappings.get(curr_conn) {
            if conn_stack.contains(&new_conn) {
                return Err(CompError::ref_nw(
                    &urgi.module,
                    CompErrorKind::Unknown(format!(
                        "Shares go through a combinational loop of muxes. Muxes: {:?}",
                        conn_stack
                    )),
                ));
            }
            curr_conn = new_conn;
            conn_stack.push(new_conn);
        }
        *conn = curr_conn.clone();
    }
    Ok(urgi)
}

fn sort_timed_gadgets<'a>(urgi: &UnrolledGadgetInternals<'a>) -> Vec<Name<'a>> {
    let mut deps = petgraph::Graph::new();
    let nodes = urgi
        .subgadgets
        .keys()
        .map(|sgi_name| (sgi_name, deps.add_node(sgi_name)))
        .collect::<HashMap<_, _>>();
    for (sgi_name, sgi) in urgi.subgadgets.iter() {
        for conn in sgi.input_connections.values() {
            if let TConnection::GadgetOutput { gadget_name, .. } = conn {
                let src = if let Some(src) = nodes.get(gadget_name) {
                    *src
                } else {
                    panic!(
                        "gadget {:?} not found (connection from gadget {:?}), gadgets: {:?}",
                        gadget_name,
                        sgi_name,
                        urgi.subgadgets.keys().collect::<Vec<_>>()
                    );
                };
                let dest = nodes[sgi_name];
                deps.add_edge(src, dest, ());
            }
        }
    }
    petgraph::algo::toposort(&deps, None)
        .unwrap()
        .into_iter()
        .map(|idx| *deps[idx])
        .collect::<Vec<_>>()
}

fn conn_valid<'a>(
    connection: &TConnection<'a>,
    sg: &HashMap<Name<'a>, TGadgetInstance<'a>>,
    inputs: &HashSet<TSharing<'a>>,
    gadgets_validity: &HashMap<Name<'a>, Validity>,
) -> Validity {
    match connection {
        TConnection::GadgetOutput { gadget_name, .. } => {
            if sg.contains_key(gadget_name) {
                gadgets_validity[gadget_name]
            } else {
                Validity::Invalid
            }
        }
        TConnection::Input(input) => {
            if inputs.contains(input) {
                Validity::Valid
            } else {
                Validity::Invalid
            }
        }
        TConnection::Invalid(_) => Validity::Invalid,
    }
}

fn gadget_valid<'a: 'b, 'b>(
    connections: &'b HashMap<gadgets::Sharing<'a>, TConnection<'a>>,
    sg: &'b HashMap<Name, TGadgetInstance<'a>>,
    inputs: &'b HashSet<TSharing<'a>>,
    gadgets_validity: &HashMap<Name, Validity>,
) -> Result<Validity, Vec<(&'b gadgets::Sharing<'a>, &'b TConnection<'a>, Validity)>> {
    let validities = connections
        .iter()
        .map(|(port, conn)| (port, conn, conn_valid(conn, sg, inputs, gadgets_validity)))
        .collect::<Vec<_>>();
    let seen_valid = validities.iter().any(|(_, _, v)| *v == Validity::Valid);
    let seen_invalid = validities.iter().any(|(_, _, v)| *v == Validity::Invalid);
    match (seen_valid, seen_invalid) {
        (true, true) => Err(validities),
        (true, false) => Ok(Validity::Valid),
        (false, true) => Ok(Validity::Invalid),
        (false, false) => Ok(Validity::Any),
    }
}

fn get_validities<'a>(
    urgi: &UnrolledGadgetInternals<'a>,
    gadgets_validity: &HashMap<Name, Validity>,
    validities: &[(&Sharing<'a>, &TConnection<'a>, Validity)],
) -> Vec<(Sharing<'a>, Validity, Vec<Latency>)> {
    validities
        .iter()
        .map(|(sharing, conn, validity)| {
            let valid_cycles = (0..urgi.n_cycles)
                .filter(|cycle| {
                    conn_valid(
                        &retime_connection(conn, *cycle),
                        &urgi.subgadgets,
                        &urgi.inputs,
                        &gadgets_validity,
                    ) == Validity::Valid
                })
                .collect::<Vec<_>>();
            (**sharing, *validity, valid_cycles)
        })
        .collect()
}

pub fn do_not_compute_invalid<'a>(
    mut urgi: UnrolledGadgetInternals<'a>,
) -> Result<UnrolledGadgetInternals<'a>, CompErrors<'a>> {
    println!("not computing invalid...");
    let sorted_gadgets = sort_timed_gadgets(&urgi);
    let mut gadgets_validity: HashMap<Name, Validity> = HashMap::new();
    let mut errors_mixed = Vec::new();
    for sgi_name in sorted_gadgets.iter() {
        let sgi = &urgi.subgadgets[sgi_name];
        let valid = gadget_valid(
            &sgi.input_connections,
            &urgi.subgadgets,
            &urgi.inputs,
            &gadgets_validity,
        );
        match valid {
            Ok(validity) => {
                gadgets_validity.insert(sgi_name.clone(), validity);
            }
            Err(validities) => {
                gadgets_validity.insert(sgi_name.clone(), Validity::Invalid);
                errors_mixed.push((sgi_name, validities));
            }
        }
    }
    if !errors_mixed.is_empty() {
        let res: Vec<CompError<'a>> = errors_mixed
            .into_iter()
            .map(|(sgi_name, validities)| CompError {
                module: Some(urgi.module.clone()),
                net: None,
                kind: CompErrorKind::MixedValidity {
                    validities: get_validities(&urgi, &gadgets_validity, &validities),
                    gadgets_validity: gadgets_validity.clone(),
                    sgi: urgi.subgadgets[sgi_name].clone(),
                    subgadget: *sgi_name,
                },
            })
            .collect();
        return Err(CompErrors::new(res));
    }
    let sg = &urgi.subgadgets;
    let inputs = &urgi.inputs;
    urgi.output_connections
        .retain(|_, conn| conn_valid(&*conn, sg, inputs, &gadgets_validity) == Validity::Valid);
    for i in (0..sorted_gadgets.len()).rev() {
        let sgi_name = &sorted_gadgets[i];
        match gadgets_validity[sgi_name] {
            Validity::Valid => {}
            Validity::Invalid => {
                urgi.subgadgets.remove(sgi_name);
            }
            Validity::Any => {
                let used = (i + 1..sorted_gadgets.len())
                    .filter_map(|j| urgi.subgadgets.get(&sorted_gadgets[j]))
                    .flat_map(|sgi2| sgi2.input_connections.values())
                    .any(|conn| {
                        if let TConnection::GadgetOutput { gadget_name, .. } = conn {
                            gadget_name == sgi_name
                        } else {
                            false
                        }
                    });
                if !used {
                    urgi.subgadgets.remove(sgi_name);
                }
            }
        }
    }

    Ok(urgi)
}

pub fn check_valid_outputs<'a>(
    urgi: &UnrolledGadgetInternals<'a>,
    gadget: &Gadget<'a>,
) -> Result<(), CompError<'a>> {
    let missing_outputs: Vec<(gadgets::Sharing, u32)> = gadget
        .outputs
        .iter()
        .filter(|(sharing, lat)| !urgi.output_connections.contains_key(&(**sharing, **lat)))
        .map(|(sharing, lat)| (*sharing, *lat))
        .collect::<Vec<_>>();
    let excedentary_outputs = urgi
        .output_connections
        .keys()
        .filter(|(sharing, lat)| gadget.outputs.get(sharing) != Some(lat))
        .map(|(sharing, lat)| (*sharing, *lat))
        .collect::<Vec<_>>();
    if !missing_outputs.is_empty() {
        return Err(CompError::ref_nw(
            &urgi.module,
            CompErrorKind::OutputNotValid(missing_outputs),
        ));
    }
    if !excedentary_outputs.is_empty() {
        return Err(CompError::ref_nw(
            &urgi.module,
            CompErrorKind::ExcedentaryOutput(excedentary_outputs),
        ));
    }
    Ok(())
}

pub fn check_state_cleared<'a>(
    urgi: &UnrolledGadgetInternals<'a>,
    gadgets: &Gadgets<'a>,
    n_cycles: Latency,
) -> Result<(), CompError<'a>> {
    for ((sgi_name, sgi_cycle), sgi) in urgi.subgadgets.iter() {
        for (output, out_lat) in gadgets[sgi.base.kind].outputs.iter() {
            if sgi_cycle + out_lat > n_cycles - 1 {
                return Err(CompError::ref_nw(
                    &urgi.module,
                    CompErrorKind::LateOutput(
                        sgi_cycle + out_lat - n_cycles + 1,
                        (*sgi_name).to_owned(),
                        *output,
                    ),
                ));
            }
        }
    }
    Ok(())
}

pub fn check_all_inputs_exist(urgi: &UnrolledGadgetInternals) -> bool {
    urgi.subgadgets
        .iter()
        .flat_map(|(_, sgi)| sgi.input_connections.values())
        .chain(urgi.output_connections.iter().map(|(_, c)| c))
        .all(|c| match c {
            TConnection::GadgetOutput { gadget_name, .. } => {
                urgi.subgadgets.contains_key(gadget_name)
            }
            TConnection::Input(input) => urgi.inputs.contains(input),
            TConnection::Invalid(_) => false,
        })
}

pub fn check_sec_prop<'a>(
    urgi: &UnrolledGadgetInternals<'a>,
    gadget: &Gadget<'a>,
    gadgets: &Gadgets<'a>,
) -> Result<(), CompError<'a>> {
    match gadget.prop {
        netlist::GadgetProp::Affine => {
            for (sgi_name, sgi) in urgi.subgadgets.iter() {
                if !gadgets[sgi.base.kind].prop.is_affine() {
                    return Err(CompError::ref_nw(
                        &urgi.module,
                        CompErrorKind::Unknown(format!("Subgadget {:?} is not Affine", sgi_name)),
                    ));
                }
            }
        }
        netlist::GadgetProp::PINI => {
            for (sgi_name, sgi) in urgi.subgadgets.iter() {
                if !gadgets[sgi.base.kind].is_pini() {
                    return Err(CompError::ref_nw(
                        &urgi.module,
                        CompErrorKind::Unknown(format!("Subgadget {:?} is not PINI", sgi_name)),
                    ));
                }
            }
        }
        _ => {
            unimplemented!();
        }
    }
    Ok(())
}

// Returns None if input is late
pub fn random_to_input<'a>(
    internals: &gadget_internals::GadgetInternals<'a>,
    module: &'a yosys::Module,
    controls: &mut clk_vcd::ModuleControls,
    trandom: &TRandom<'a>,
    sg_name: &Name<'a>,
    rnd_name: &gadgets::Random<'a>,
) -> Result<
    (
        Option<(gadgets::Random<'a>, gadgets::Latency)>,
        Vec<(RndConnection<'a>, gadgets::Latency)>,
    ),
    CompError<'a>,
> {
    let mut trandom_w: Vec<(RndConnection<'a>, gadgets::Latency)> = vec![(trandom.0, trandom.1)];
    loop {
        let rnd_to_add = match &trandom_w[trandom_w.len() - 1] {
            (RndConnection::Invalid(bit), _) => {
                return Err(CompError::ref_nw(
                    module,
                    CompErrorKind::InvalidRandom(trandom_w.clone(), *sg_name, *rnd_name, *bit),
                ));
            }
            (RndConnection::Port(rnd), cycle) => {
                return Ok((Some((*rnd, *cycle)), trandom_w.clone()));
            }
            (RndConnection::Gate(gate_id), cycle) => match &internals.rnd_gates[&gate_id] {
                gadget_internals::RndGate::Reg { input: new_conn } => {
                    if *cycle == 0 {
                        return Err(CompError::ref_nw(module, CompErrorKind::Unknown(format!("Randomness for random {} of gadget {:?} comes from a cycle before cycle 0 (through reg {:?})", rnd_name, sg_name, gate_id))));
                    }
                    (*new_conn, cycle - 1)
                }
                gadget_internals::RndGate::Mux { ina, inb } => {
                    let (var_name, offset) =
                        netlist::get_names(module, module.cells[gate_id.0].connections["S"][0])
                            .next()
                            .expect("No names for net");
                    let var_name = netlist::format_name(var_name);
                    match controls.lookup(vec![var_name], *cycle as usize, offset)? {
                        None => {
                            return Ok((None, trandom_w.clone()));
                        }
                        Some(clk_vcd::VarState::Scalar(vcd::Value::V0)) => (*ina, *cycle),
                        Some(clk_vcd::VarState::Scalar(vcd::Value::V1)) => (*inb, *cycle),
                        Some(clk_vcd::VarState::Vector(_)) => unreachable!(),
                        Some(sel @ clk_vcd::VarState::Scalar(vcd::Value::Z))
                        | Some(sel @ clk_vcd::VarState::Uninit)
                        | Some(sel @ clk_vcd::VarState::Scalar(vcd::Value::X)) => {
                            return Err(CompError::ref_nw(module, CompErrorKind::Unknown(format!(
                                    "Invalid control signal {:?} for mux {} at cycle {} for randomness", sel,
                                    gate_id.0, cycle
                                ))));
                        }
                    }
                }
            },
        };
        trandom_w.push(rnd_to_add);
    }
}

pub fn randoms_input_timing<'b, 'c, 'a: 'b + 'c>(
    urgi: &'b UnrolledGadgetInternals<'a>,
    internals: &'c gadget_internals::GadgetInternals<'a>,
    controls: &mut clk_vcd::ModuleControls,
) -> Result<HashMap<(gadgets::Random<'a>, Latency), (Name<'a>, gadgets::Random<'a>)>, CompErrors<'a>>
{
    let mut res =
        HashMap::<(gadgets::Random<'a>, gadgets::Latency), (Name<'a>, gadgets::Random<'a>)>::new();
    let mut traces = HashMap::<
        (gadgets::Random, gadgets::Latency),
        Vec<(RndConnection, gadgets::Latency)>,
    >::new();
    let mut errors: Vec<CompError<'a>> = Vec::<CompError<'a>>::new();
    for (sg_name, sgi) in urgi.subgadgets.iter() {
        for (conn, trandom) in sgi.random_connections.iter() {
            match random_to_input(internals, &urgi.module, controls, trandom, sg_name, conn) {
                Ok((None, _)) => {
                    // A late random. Due to causality, it can only be an issue for correctness of
                    // late outputs. Either we forbid late outputs, or we don't check their
                    // correctness.  Therefore, a late random is never an issue, we can forget it.
                }
                Ok((Some(rnd_in), trandom_w)) => {
                    if let Some(prev) = res.get(&rnd_in) {
                        let trace = traces[&rnd_in].clone();
                        errors.push(CompError::ref_nw(
                            &urgi.module,
                            CompErrorKind::MultipleUseRandom {
                                random: rnd_in,
                                uses: vec![(*prev, trace), ((*sg_name, *conn), trandom_w)],
                            },
                        ));
                    } else {
                        res.insert(rnd_in.clone(), (*sg_name, *conn));
                        traces.insert(rnd_in, trandom_w);
                    }
                }
                Err(err) => {
                    errors.push(err);
                }
            }
        }
    }
    if errors.is_empty() {
        Ok(res)
    } else {
        Err(CompErrors::<'a>::new(errors))
    }
}

pub fn list_gadgets<'a>(urgi: &UnrolledGadgetInternals<'a>) -> Vec<(GName<'a>, String)> {
    let mut gadgets = HashMap::new();
    for (gadget, cycle) in urgi.subgadgets.keys() {
        gadgets
            .entry(gadget)
            .or_insert_with(Vec::new)
            .push(*cycle as usize);
    }
    let mut res = gadgets
        .into_iter()
        .map(|(g, c)| (*g, crate::utils::format_set(c.into_iter())))
        .collect::<Vec<_>>();
    res.sort_unstable();
    res
}

// rnd_timings to map: port -> offsets for each cycle
pub fn abstract_rnd_timings<'a>(
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

pub fn rnd_timing_disp<'a>(
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
