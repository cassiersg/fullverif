use crate::error::{CompError, CompErrorKind};
use crate::gadgets::Gadget;
use crate::netlist;
use crate::timed_gadgets::UnrolledGadgetInternals;

pub fn check_sec_prop<'a, 'b>(
    urgi: &UnrolledGadgetInternals<'a, 'b>,
    gadget: &Gadget<'a>,
) -> Result<(), CompError<'a>> {
    match gadget.prop {
        netlist::GadgetProp::Affine => {
            for (sgi_name, sgi) in urgi.subgadgets.iter() {
                if !sgi.base.kind.prop.is_affine() {
                    return Err(CompError::ref_nw(
                        &urgi.internals.gadget.module,
                        CompErrorKind::Other(format!("Subgadget {:?} is not Affine", sgi_name)),
                    ));
                }
            }
        }
        netlist::GadgetProp::PINI => {
            for (sgi_name, sgi) in urgi.subgadgets.iter() {
                if !sgi.base.kind.is_pini() {
                    return Err(CompError::ref_nw(
                        &urgi.internals.gadget.module,
                        CompErrorKind::Other(format!("Subgadget {:?} is not PINI", sgi_name)),
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
