use crate::error::{CompError, CompErrorKind, CompErrors, DBitVal};
use crate::gadgets::*;
use std::collections::{hash_map, HashMap};
use yosys_netlist_json as yosys;

pub type GName<'a> = &'a str;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Connection<'a> {
    GadgetOutput {
        gadget_name: GName<'a>,
        output: Sharing<'a>,
    },
    Input(Sharing<'a>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GadgetInstance<'a, 'b> {
    pub kind: &'b Gadget<'a>,
    pub input_connections: HashMap<Sharing<'a>, Connection<'a>>,
    pub random_connections: HashMap<Random<'a>, RndConnection<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GadgetInternals<'a, 'b> {
    pub gadget: &'b Gadget<'a>,
    pub rnd_gates: HashMap<RndGateId<'a>, RndGate<'a>>,
    pub subgadgets: HashMap<GName<'a>, GadgetInstance<'a, 'b>>,
    pub output_connections: HashMap<Sharing<'a>, Connection<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RndGate<'a> {
    Reg {
        input: RndConnection<'a>,
    },
    Mux {
        ina: RndConnection<'a>,
        inb: RndConnection<'a>,
    },
}

pub type RndGateId<'a> = (&'a str, u32);

#[derive(Copy, Clone, Debug, Derivative)]
#[derivative(
    PartialEq = "feature_allow_slow_enum",
    PartialOrd = "feature_allow_slow_enum",
    Ord = "feature_allow_slow_enum",
    Hash,
    Eq
)]
pub enum RndConnection<'a> {
    Port(Random<'a>),
    Gate(RndGateId<'a>),
    Invalid(
        #[derivative(PartialOrd = "ignore")]
        #[derivative(Ord = "ignore")]
        #[derivative(PartialEq = "ignore")]
        #[derivative(Hash = "ignore")]
        yosys::BitVal,
    ),
}

pub fn module2internals<'a, 'b>(
    gadget: &'b Gadget<'a>,
    lib_gadgets: &'b Gadgets<'a>,
) -> Result<GadgetInternals<'a, 'b>, CompErrors<'a>> {
    // List subgadgets.
    let mut subgadgets = HashMap::new();
    let (rnd_gates, rnd_map) = module2randoms(gadget, lib_gadgets)?;
    for (cell_name, cell) in gadget.module.cells.iter() {
        if let Some(sg) = lib_gadgets.get(cell.cell_type.as_str()) {
            let random_connections = sg
                .randoms
                .keys()
                .map(|sg_rnd| -> Result<_, CompErrors<'a>> {
                    let rnd_bitval = &cell.connections[sg_rnd.port_name][sg_rnd.offset as usize];
                    let rnd = rnd_map.get(rnd_bitval).ok_or_else(|| {
                        CompError::ref_nw(
                            gadget.module,
                            CompErrorKind::Other(format!(
                                "Bad random bit for port {:?} of subgadget {:?}",
                                &sg_rnd.port_name, cell_name
                            )),
                        )
                    })?;
                    Ok((*sg_rnd, *rnd))
                })
                .collect::<Result<HashMap<_, _>, _>>()?;
            subgadgets.insert(
                cell_name.as_str(),
                GadgetInstance {
                    kind: sg,
                    input_connections: HashMap::new(),
                    random_connections,
                },
            );
        }
    }
    // List available sharings and check that they are unique.
    let input_sharings_iter =
        gadget
            .inputs
            .keys()
            .map(|input_sharing| -> Result<_, CompError<'a>> {
                Ok((
                    get_port_bits(input_sharing, gadget.module, gadget.order),
                    Connection::Input(*input_sharing),
                ))
            });
    let sg_output_sharings_iter = subgadgets.iter().flat_map(|(gadget_name, gadget_inst)| {
        gadget_inst.kind.outputs.keys().map(move |output_sharing| {
            Ok((
                get_connection_bits(
                    gadget.module,
                    gadget_name,
                    output_sharing,
                    &gadget.module.cells[*gadget_name].connections,
                    gadget.order,
                )?,
                Connection::GadgetOutput {
                    gadget_name,
                    output: *output_sharing,
                },
            ))
        })
    });
    let mut sharings = HashMap::new();
    for sharing in input_sharings_iter.chain(sg_output_sharings_iter) {
        let (bits, sharing) = sharing?;
        if let hash_map::Entry::Vacant(entry) = sharings.entry(bits) {
            entry.insert(sharing);
        } else {
            return Err(CompErrors::new(vec![CompError {
                module: Some(gadget.module.clone()),
                net: Some(
                    gadget
                        .module
                        .netnames
                        .values()
                        .find(|netname| netname.bits == bits)
                        .unwrap()
                        .clone(),
                ),
                kind: CompErrorKind::MultipleSourceSharing(vec![sharing, sharings[bits]]),
            }]));
        }
    }
    // Connect subgadget inputs to sharings
    for (sg_name, sg) in subgadgets.iter_mut() {
        for input_name in sg.kind.inputs.keys() {
            let bits = get_connection_bits(
                gadget.module,
                sg_name,
                input_name,
                &gadget.module.cells[*sg_name].connections,
                gadget.order,
            )?;
            let sharing = sharings.get(bits).ok_or_else(|| {
                CompError::ref_nw(
                    gadget.module,
                    CompErrorKind::MissingSourceSharing {
                        subgadget: sg_name,
                        sharing: *input_name,
                        nets: bits,
                    },
                )
            })?;
            sg.input_connections
                .insert(input_name.clone(), sharing.clone());
        }
    }
    // Connect output connections of the gadget
    let mut output_connections = HashMap::new();
    for output_name in gadget.outputs.keys() {
        let bits = get_port_bits(output_name, gadget.module, gadget.order);
        let sharing = sharings.get(bits).ok_or_else(|| {
            CompError::ref_sn(
                gadget.module,
                &output_name.port_name,
                CompErrorKind::MissingSourceSharingOut(*output_name),
            )
        })?;
        output_connections.insert(output_name.clone(), sharing.clone());
    }
    Ok(GadgetInternals {
        gadget,
        rnd_gates,
        subgadgets,
        output_connections,
    })
}

/// Checks the the Gadget is respects sharings: that each use of a sharing (input or
/// generated by a sub-gadget) happens as a whole as an input sharing to a sub-gadget or as an
/// output sharing.
pub fn check_gadget_preserves_sharings<'a, 'b>(
    gadgets: &Gadgets<'a>,
    internals: &GadgetInternals<'a, 'b>,
) -> Result<(), CompError<'a>> {
    let gadget = internals.gadget;
    // List wires that carry a share, that is, wires that are an output of a sub-gadget or
    // belong to an input sharing.
    let mut sharings: HashMap<&[yosys::BitVal], Connection> = HashMap::new();
    for (sg_name, sgi) in internals.subgadgets.iter() {
        for (output_name, _) in sgi.kind.outputs.iter() {
            sharings.insert(
                get_connection_bits(
                    gadget.module,
                    sg_name,
                    output_name,
                    &gadget.module.cells[*sg_name].connections,
                    gadget.order,
                )?,
                Connection::GadgetOutput {
                    gadget_name: sg_name,
                    output: *output_name,
                },
            );
        }
    }
    for (input_name, _) in gadget.inputs.iter() {
        sharings.insert(
            get_port_bits(input_name, gadget.module, gadget.order),
            Connection::Input(*input_name),
        );
    }
    let shares: HashMap<_, _> = sharings
        .iter()
        .flat_map(|(sharing, conn)| sharing.iter().map(move |bit| (bit, conn)))
        .collect();
    // For each cell, and for each of its input ports, check that either the port is a sharing
    // port, or none of the bits are shares.
    for (cell_name, cell) in gadget.module.cells.iter() {
        for (conn_name, conn) in cell.connections.iter() {
            if let Some(gadget) = gadgets.get(cell.cell_type.as_str()) {
                let mut ports = gadget.inputs.keys().chain(gadget.outputs.keys());
                if ports.any(|p| p.port_name == conn_name) {
                    // this is a sharing, already checked that it is a correct sharing when
                    // building the internals of the module
                    continue;
                }
            }
            // connection is not a sharing. Check it doesn't use shares
            for (i, bitval) in conn.iter().enumerate() {
                if let Some(conn) = shares.get(bitval) {
                    return Err(CompError::ref_nw(
                        gadget.module,
                        CompErrorKind::BadShareUse(**conn, cell_name.clone(), conn_name.clone(), i),
                    ));
                }
            }
        }
    }
    for (port_name, port) in gadget.module.ports.iter() {
        let mut ports = gadget.inputs.keys().chain(gadget.outputs.keys());
        if ports.all(|p| p.port_name != port_name) {
            // this is not a sharing, check it doesn't use shares
            for (i, bitval) in port.bits.iter().enumerate() {
                if let Some(conn) = shares.get(bitval) {
                    return Err(CompError::ref_nw(
                        gadget.module,
                        CompErrorKind::BadShareUse(**conn, String::new(), port_name.clone(), i),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn module2randoms<'a>(
    gadget: &Gadget<'a>,
    lib_gadgets: &Gadgets<'a>,
) -> Result<
    (
        HashMap<RndGateId<'a>, RndGate<'a>>,
        HashMap<&'a yosys::BitVal, RndConnection<'a>>,
    ),
    CompErrors<'a>,
> {
    let mut wires2rnds: HashMap<&yosys::BitVal, RndConnection> = gadget
        .randoms
        .keys()
        .map(|rnd| {
            (
                &gadget.module.ports[rnd.port_name].bits[rnd.offset as usize],
                RndConnection::Port(*rnd),
            )
        })
        .collect();
    let mut to_explore: Vec<&yosys::BitVal> = wires2rnds.keys().cloned().collect();
    let mut rnd_gates: HashMap<RndGateId, RndGate> = HashMap::new();
    let bit_uses: HashMap<yosys::BitVal, Vec<_>> = list_wire_uses(gadget.module);
    let clock_bitval = gadget
        .clock
        .as_ref()
        .map(|clk| &gadget.module.netnames[*clk].bits);
    let v = Vec::new();
    while let Some(bitval) = to_explore.pop() {
        for (cell_name, port_name, offset) in bit_uses
            .get(bitval)
            .unwrap_or_else(|| {
                if false {
                    eprintln!("WARNING: No use for bit {}", DBitVal(bitval, gadget.module));
                }
                &v
            })
            .iter()
        {
            let gate_id = (*cell_name, *offset);
            if let std::collections::hash_map::Entry::Vacant(entry) = rnd_gates.entry(gate_id) {
                let cell = &gadget.module.cells[*cell_name];
                let output = match cell.cell_type.as_str() {
                    "$dff" => {
                        assert_eq!(
                            Some(&cell.connections["CLK"]),
                            clock_bitval,
                            "Wrong clock on random DFF"
                        );
                        let pol = &cell.parameters["CLK_POLARITY"];
                        assert!(
                            pol == &yosys::AttributeVal::S("1".to_string())
                                || pol == &yosys::AttributeVal::N(1),
                            "Wrong clock polarity: {:?}",
                            pol
                        );
                        entry.insert(RndGate::Reg {
                            input: wires2rnds[bitval],
                        });
                        Some(&cell.connections["Q"][*offset as usize])
                    }
                    "$mux" => {
                        entry.insert(RndGate::Mux {
                            ina: RndConnection::Gate(("", 0)),
                            inb: RndConnection::Gate(("", 0)),
                        });
                        Some(&cell.connections["Y"][*offset as usize])
                    }
                    _ => {
                        if lib_gadgets
                            .get(cell.cell_type.as_str())
                            .map(|gadget| {
                                !gadget.randoms.contains_key(&Random {
                                    port_name,
                                    offset: *offset,
                                })
                            })
                            .unwrap_or(true)
                        {
                            return Err(CompErrors::new(vec![CompError::ref_nw(gadget.module, CompErrorKind::Other(format!("The cell {} (port {}[{}]) is connected to a random wire but is not a gadget, mux or DFF (type: {})", cell_name, port_name, offset, cell.cell_type)))]));
                        } else {
                            None
                        }
                    }
                };
                if let Some(output) = output {
                    wires2rnds.entry(output).or_insert_with(|| {
                        to_explore.push(output);
                        RndConnection::Gate(gate_id)
                    });
                }
            }
        }
    }
    for ((gate_name, offset), ref mut gate) in rnd_gates.iter_mut() {
        if let RndGate::Mux {
            ref mut ina,
            ref mut inb,
        } = gate
        {
            let cell = &gadget.module.cells[*gate_name];
            let bita = &cell.connections["A"][*offset as usize];
            let bitb = &cell.connections["B"][*offset as usize];
            match (wires2rnds.get(bita), wires2rnds.get(bitb)) {
                (Some(conna), Some(connb)) => {
                    *ina = *conna;
                    *inb = *connb;
                }
                (None, None) => {
                    unreachable!();
                }
                (Some(conna), None) => {
                    *ina = *conna;
                    *inb = RndConnection::Invalid(*bitb);
                }
                (None, Some(connb)) => {
                    *ina = RndConnection::Invalid(*bita);
                    *inb = *connb;
                }
            }
        }
    }
    println!("finished randoms");
    Ok((rnd_gates, wires2rnds))
}

fn get_port_bits<'a>(
    sharing: &Sharing,
    module: &'a yosys::Module,
    order: u32,
) -> &'a [yosys::BitVal] {
    let base = (sharing.pos * order) as usize;
    &module.ports[sharing.port_name].bits[base..base + (order as usize)]
}

fn get_connection_bits<'a, 'b>(
    module: &yosys::Module,
    gadget_name: &str,
    sharing: &Sharing<'a>,
    connections: &'b HashMap<String, Vec<yosys::BitVal>>,
    order: u32,
) -> Result<&'b [yosys::BitVal], CompError<'a>> {
    let base = (sharing.pos * order) as usize;
    let res = &connections[sharing.port_name][base..base + (order as usize)];
    for (i, bitval) in res.iter().enumerate() {
        if let yosys::BitVal::S(_) = bitval {
            return Err(CompError::ref_nw(
                module,
                CompErrorKind::ConstantShare(gadget_name.to_owned(), *sharing, i as u32),
            ));
        }
    }
    Ok(res)
}

fn list_wire_uses<'a>(
    module: &'a yosys::Module,
) -> HashMap<yosys::BitVal, Vec<(GName<'a>, &'a str, u32)>> {
    let mut res = HashMap::new();
    for (cell_name, cell) in module.cells.iter() {
        for (conn, bits) in cell.connections.iter() {
            if cell.port_directions[conn] == yosys::PortDirection::Input {
                for (offset, bit) in bits.iter().enumerate() {
                    res.entry(bit.clone()).or_insert_with(Vec::new).push((
                        cell_name.as_str(),
                        conn.as_str(),
                        offset as u32,
                    ));
                }
            }
        }
    }
    res
}
