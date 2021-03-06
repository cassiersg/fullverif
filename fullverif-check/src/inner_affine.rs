use crate::error::{CompError, CompErrorKind};
use crate::gadgets::Gadget;
use std::collections::HashMap;
use yosys_netlist_json as yosys;

/// Verify that the gadget is a trivial implementation of an affine function.
/// That is, verify that is is structurally made of d isolated sub-gadgets, each sub-gadget taking
/// care of on share of the input sharings ("circuit share"/"DOM" isolation).
pub fn check_inner_affine<'a>(gadget: &Gadget<'a>) -> Result<(), CompError<'a>> {
    let mut wires_as_cell_inputs: HashMap<yosys::BitVal, Vec<(&yosys::Cell, &str, u32)>> =
        HashMap::new();
    for cell in gadget.module.cells.values() {
        for (port, bitvals) in cell.connections.iter() {
            for (i, bitval) in bitvals.iter().enumerate() {
                wires_as_cell_inputs
                    .entry(*bitval)
                    .or_insert_with(Vec::new)
                    .push((&cell, port, i as u32));
            }
        }
    }
    let mut tagged_wires: HashMap<yosys::BitVal, u32> = HashMap::new();
    let mut wires_to_analyze: Vec<yosys::BitVal> = Vec::new();
    for input in gadget.inputs.keys() {
        for (i, bv) in gadget.sharing_bits(*input).iter().enumerate() {
            insert_or_fail(
                gadget,
                &mut tagged_wires,
                &mut wires_to_analyze,
                *bv,
                i as u32,
            )?;
        }
    }
    while let Some(bv) = wires_to_analyze.pop() {
        let share = tagged_wires[&bv];
        for (cell, in_port, in_offset) in
            wires_as_cell_inputs.get(&bv).unwrap_or(&Vec::new()).iter()
        {
            for (port, direction) in cell.port_directions.iter() {
                if port != in_port {
                    if isolating_gate(&cell.cell_type, in_port, port) {
                        insert_or_fail(
                            gadget,
                            &mut tagged_wires,
                            &mut wires_to_analyze,
                            cell.connections[port][*in_offset as usize],
                            share,
                        )?;
                    } else if *direction != yosys::PortDirection::Input {
                        for bit in cell.connections[port].iter() {
                            insert_or_fail(
                                gadget,
                                &mut tagged_wires,
                                &mut wires_to_analyze,
                                *bit,
                                share,
                            )?;
                        }
                    }
                }
            }
        }
    }
    for output in gadget.outputs.keys() {
        for (i, bv) in gadget.sharing_bits(*output).iter().enumerate() {
            insert_or_fail(
                gadget,
                &mut tagged_wires,
                &mut wires_to_analyze,
                *bv,
                i as u32,
            )?;
        }
    }
    Ok(())
}

/// Annotate that wire bv is in the given share (or fail), then add bv to the stack of to be
/// analyzed wires if it was not yet tagged.
fn insert_or_fail<'a>(
    gadget: &Gadget<'a>,
    tagged_wires: &mut HashMap<yosys::BitVal, u32>,
    wires_to_analyze: &mut Vec<yosys::BitVal>,
    bv: yosys::BitVal,
    share: u32,
) -> Result<(), CompError<'a>> {
    match tagged_wires.entry(bv) {
        std::collections::hash_map::Entry::Occupied(e) => {
            if *e.get() == share {
                Ok(())
            } else {
                Err(CompError::ref_nw(
                    gadget.module,
                    CompErrorKind::Other(format!(
                        "Gadget is not affine: wire {:?} belongs to both share {} and {}.",
                        bv,
                        e.get(),
                        share
                    )),
                ))
            }
        }
        std::collections::hash_map::Entry::Vacant(e) => {
            e.insert(share);
            wires_to_analyze.push(bv);
            Ok(())
        }
    }
}

/// Checks whether an input wire is connected only to the corresponding (i.e. with same offset)
/// wire of the output port.
fn isolating_gate(cell: &str, in_port: &str, out_port: &str) -> bool {
    match (cell, in_port, out_port) {
        ("$not", "A", "Y")
        | ("$and", "A", "Y")
        | ("$and", "B", "Y")
        | ("$or", "A", "Y")
        | ("$or", "B", "Y")
        | ("$xor", "A", "Y")
        | ("$xor", "B", "Y")
        | ("$xnor", "A", "Y")
        | ("$xnor", "B", "Y")
        | ("$mux", "A", "Y")
        | ("$mux", "B", "Y")
        | ("$dff", "D", "Q") => true,
        _ => false,
    }
}
