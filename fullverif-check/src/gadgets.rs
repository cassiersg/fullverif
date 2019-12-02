use crate::error::{CompError, CompErrorKind};
use crate::netlist::{self, GadgetProp, GadgetStrat, WireAttrs};
use std::collections::HashMap;
use yosys_netlist_json as yosys;

/// Time unit, in clock cycles
pub type Latency = u32;

pub type Latencies = Vec<u32>;

/// Description of a bit of a random port of a gadget
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Random<'a> {
    pub port_name: &'a str,
    pub offset: u32,
}

/// Id of an input/output sharing of a gadget
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sharing<'a> {
    pub port_name: &'a str,
    pub pos: u32,
}

/// Id of a functional input.
pub type Input<'a> = (Sharing<'a>, Latency);

/// A gadget definition.
// Invariant: all output latencies are >= input and randomness latencies
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gadget<'a> {
    /// Name of the module
    pub name: GKind<'a>,
    /// Verilog module netlist
    pub module: &'a yosys::Module,
    /// Name of the clock signal
    pub clock: Option<&'a str>,
    /// Input sharings
    pub inputs: HashMap<Sharing<'a>, Latencies>,
    /// Output sharings
    pub outputs: HashMap<Sharing<'a>, Latency>,
    /// Randomness inputs
    pub randoms: HashMap<Random<'a>, Option<Latencies>>,
    /// Security property
    pub prop: GadgetProp,
    /// Strategy to be used to prove the security
    pub strat: GadgetStrat,
    /// Masking order
    pub order: u32,
}

/// The name of a gadget.
pub type GKind<'a> = phantom_newtype::Id<Gadget<'a>, &'a str>;

/// A series of gadget declarations
pub type Gadgets<'a> = HashMap<GKind<'a>, Gadget<'a>>;

/// Convert a module to a gadget.
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
            CompErrorKind::MissingAnnotation("fv_prop".to_owned()),
        ));
    };
    // Decide if gadget is composite or not.
    let strat = netlist::module_strat(module)?;
    let order = netlist::module_order(module)?;
    // Initialize gadget.
    let mut res = Gadget {
        name: name.into(),
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
            (WireAttrs::Sharing { latencies, count }, dir @ yosys::PortDirection::Input)
            | (WireAttrs::Sharing { latencies, count }, dir @ yosys::PortDirection::Output) => {
                if port.bits.len() as u32 != order * count {
                    return Err(CompError::ref_sn(
                        module,
                        port_name,
                        CompErrorKind::WrongWireWidth(port.bits.len() as u32, order * count),
                    ));
                }
                for pos in 0..count {
                    if dir == yosys::PortDirection::Input {
                        res.inputs
                            .insert(Sharing { port_name, pos }, latencies.clone());
                    } else {
                        if latencies.len() != 1 {
                            return Err(CompError::ref_sn(
                        module,
                        port_name,
                        CompErrorKind::Other(format!("Outputs can be valid at only one cycle (current latencies: {:?})", latencies))));
                        }
                        res.outputs.insert(Sharing { port_name, pos }, latencies[0]);
                    }
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
                        CompErrorKind::Other(
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
    res.output_lat_ok()?;
    Ok(Some(res))
}

/// Convert a netlist to a list of gadgets.
pub fn netlist2gadgets<'a>(
    netlist: &'a yosys::Netlist,
) -> Result<HashMap<GKind<'a>, Gadget<'a>>, CompError<'a>> {
    let res = netlist
        .modules
        .iter()
        .filter_map(|(module_name, module)| {
            (|| {
                Ok(module2gadget(module, module_name)?
                    .map(|gadget| (module_name.as_str().into(), gadget)))
            })()
            .transpose()
        })
        .collect::<Result<HashMap<_, _>, _>>()?;
    Ok(res)
}

impl<'a> Gadget<'a> {
    /// Test if the gadget is annotated as PINI.
    pub fn is_pini(&self) -> bool {
        self.prop.is_pini()
            || (self.prop == netlist::GadgetProp::SNI && self.inputs.len() <= 1)
            || self.prop == netlist::GadgetProp::Mux
    }

    /// Maximum output latency
    pub fn max_output_lat(&self) -> Latency {
        self.outputs
            .values()
            .cloned()
            .max()
            .expect("No output for gadget")
    }

    /// BitVal mapping to a sharing.
    pub fn sharing_bits(&self, sharing: Sharing<'a>) -> &'a [yosys::BitVal] {
        &self.module.ports[sharing.port_name].bits[(sharing.pos * self.order) as usize..]
            [..self.order as usize]
    }

    /// Verify that the output latencies are larger than any input or random latency.
    fn output_lat_ok(&self) -> Result<(), CompError<'a>> {
        let min_o_lat = self.outputs.values().cloned().max().unwrap();
        let inputs_lats = self.inputs.values().flat_map(|x| x.iter());
        let randoms_lats = self
            .randoms
            .values()
            .filter_map(|x| x.as_ref())
            .flat_map(|x| x.iter());
        let max_in_lat = inputs_lats.chain(randoms_lats).copied().min();
        if let Some(max_in_lat) = max_in_lat {
            if max_in_lat > min_o_lat {
                return Err(CompError::ref_nw(self.module, CompErrorKind::EarlyOutput));
            }
        }
        return Ok(());
    }

    /// List the logic inputs of the gadget.
    pub fn inputs<'s>(&'s self) -> impl Iterator<Item = Input<'a>> + 's {
        self.inputs
            .iter()
            .flat_map(|(sharing, latencies)| latencies.iter().map(move |lat| (*sharing, *lat)))
    }

    /// Does the gadget have an input or output sharing with that name ?
    pub fn has_port(&self, port_name: &str) -> bool {
        let port = Sharing { port_name, pos: 0 };
        self.inputs.contains_key(&port) || self.outputs.contains_key(&port)
    }
}
