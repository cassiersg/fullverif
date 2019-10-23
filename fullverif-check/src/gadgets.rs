use crate::error::{CompError, CompErrorKind};
use crate::netlist::{self, GadgetProp, GadgetStrat, WireAttrs};
use std::collections::HashMap;
use yosys_netlist_json as yosys;

pub type Latency = u32;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Random<'a> {
    pub port_name: &'a str,
    pub offset: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sharing<'a> {
    pub port_name: &'a str,
    pub pos: u32,
}

impl<'a> Sharing<'a> {
    pub fn new(port_name: &'a str, pos: u32) -> Self {
        Self { port_name, pos }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gadget<'a> {
    pub name: &'a str,
    pub module: &'a yosys::Module,
    pub clock: Option<&'a str>,
    pub inputs: HashMap<Sharing<'a>, Latency>,
    pub outputs: HashMap<Sharing<'a>, Latency>,
    pub randoms: HashMap<Random<'a>, Option<Latency>>,
    pub prop: GadgetProp,
    pub strat: GadgetStrat,
    pub order: u32,
}

pub type GKind<'a> = &'a str;
pub type Gadgets<'a> = HashMap<GKind<'a>, Gadget<'a>>;

fn module2gadget<'a>(
    module: &'a yosys::Module,
    name: &'a str,
) -> Result<Option<Gadget<'a>>, CompError<'a>> {
    let prop = if let Some(prop) = netlist::module_prop(module)? {
        prop
    } else if let Err(CompError {
        kind: CompErrorKind::MissingAnnotation(_),
        ..
    }) = netlist::module_strat(module)
    {
        return Ok(None);
    } else {
        return Err(CompError::ref_nw(
            module,
            CompErrorKind::MissingAnnotation("psim_prop".to_owned()),
        ));
    };
    // Decide if gadget is composite or not.
    let strat = netlist::module_strat(module)?;
    let order = netlist::module_order(module)?;
    // Initialize gadget.
    let mut res = Gadget {
        name,
        module,
        clock: None,
        inputs: HashMap::new(),
        outputs: HashMap::new(),
        randoms: HashMap::new(),
        prop,
        strat,
        order,
    };
    // Classify ports of the gadgets.
    for (port_name, port) in module.ports.iter() {
        match (netlist::net_attributes(module, port_name)?, port.direction) {
            (WireAttrs::Sharing { latency, count }, dir @ yosys::PortDirection::Input)
            | (WireAttrs::Sharing { latency, count }, dir @ yosys::PortDirection::Output) => {
                if port.bits.len() as u32 != order * count {
                    return Err(CompError::ref_sn(
                        module,
                        port_name,
                        CompErrorKind::WrongWireWidth(port.bits.len() as u32, order * count),
                    ));
                }
                for pos in 0..count {
                    (if dir == yosys::PortDirection::Input {
                        &mut res.inputs
                    } else {
                        &mut res.outputs
                    })
                    .insert(Sharing::new(port_name, pos), latency);
                }
            }
            (WireAttrs::Random(randoms), yosys::PortDirection::Input) => {
                for (i, latency) in randoms.into_iter().enumerate() {
                    res.randoms.insert(
                        Random {
                            port_name,
                            offset: i as u32,
                        },
                        latency,
                    );
                }
            }
            (WireAttrs::Control, _) => {}
            (WireAttrs::Clock, _) => {
                if res.clock.is_some() {
                    return Err(CompError::ref_sn(
                        module,
                        port_name,
                        CompErrorKind::Unknown(
                            "Multiple clocks for gadget, while only one is supported.".to_string(),
                        ),
                    ));
                }
                res.clock = Some(port_name);
                if port.bits.len() != 1 {
                    return Err(CompError::ref_sn(
                        module,
                        port_name,
                        CompErrorKind::WrongWireWidth(port.bits.len() as u32, 1),
                    ));
                }
            }
            (attr, yosys::PortDirection::InOut)
            | (attr @ WireAttrs::Random(_), yosys::PortDirection::Output) => {
                return Err(CompError {
                    module: Some(module.clone()),
                    net: Some(module.netnames[port_name].clone()),
                    kind: CompErrorKind::InvalidPortDirection {
                        attr,
                        direction: port.direction,
                    },
                });
            }
        }
    }
    if res.outputs.is_empty() {
        return Err(CompError::ref_nw(module, CompErrorKind::NoOutput));
    }
    Ok(Some(res))
}

pub fn netlist2gadgets<'a>(
    netlist: &'a yosys::Netlist,
) -> Result<HashMap<GKind<'a>, Gadget<'a>>, CompError<'a>> {
    let res = netlist
        .modules
        .iter()
        .filter_map(|(module_name, module)| {
            (|| {
                    Ok(module2gadget(module, module_name)?
                        .map(|gadget| (module_name.as_str(), gadget)))
                })()
                .transpose()
        })
        .collect::<Result<HashMap<_, _>, _>>()?;
    Ok(res)
}

impl<'a> Gadget<'a> {
    pub fn is_pini(&self) -> bool {
        self.prop.is_pini() || (self.prop == netlist::GadgetProp::SNI && self.inputs.len() <= 1)
    }
    pub fn max_output_lat(&self) -> Latency {
        self.outputs
            .values()
            .cloned()
            .max()
            .expect("No output for gadget")
    }
}
