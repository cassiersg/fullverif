use crate::error::{CompError, CompErrorKind};
use crate::netlist;

pub fn check_sec_prop2<'a, 'b>(
    gadget: &crate::tg_graph::AUGIGraph<'a, 'b>,
) -> Result<(), CompError<'a>> {
    match gadget.internals.gadget.prop {
        netlist::GadgetProp::Affine => {
            for sgi_name in gadget.gadget_names() {
                if !gadget.internals.subgadgets[sgi_name.0]
                    .kind
                    .prop
                    .is_affine()
                {
                    return Err(CompError::ref_nw(
                        &gadget.internals.gadget.module,
                        CompErrorKind::Other(format!("Subgadget {:?} is not Affine", sgi_name)),
                    ));
                }
            }
        }
        netlist::GadgetProp::PINI => {
            for sgi_name in gadget.gadget_names() {
                if !gadget.internals.subgadgets[sgi_name.0].kind.is_pini() {
                    return Err(CompError::ref_nw(
                        &gadget.internals.gadget.module,
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
