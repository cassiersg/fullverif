use std::fmt;

use crate::gadget_internals::Connection;
use crate::gadget_internals::{self, GName, RndConnection};
use crate::gadgets::{self, Latency};
use crate::netlist;
use crate::timed_gadgets;
use std::collections::HashMap;
use yosys_netlist_json as yosys;

#[derive(Debug, Clone, Derivative)]
#[derivative(PartialEq, PartialOrd, Ord, Eq)]
pub struct CompError<'a> {
    pub kind: CompErrorKind<'a>,
    #[derivative(PartialOrd = "ignore")]
    #[derivative(Ord = "ignore")]
    #[derivative(PartialEq = "ignore")]
    pub module: Option<yosys::Module>,
    #[derivative(PartialOrd = "ignore")]
    #[derivative(Ord = "ignore")]
    #[derivative(PartialEq = "ignore")]
    pub net: Option<yosys::Netname>,
}

#[derive(Debug, Clone, Derivative)]
#[derivative(
    PartialEq = "feature_allow_slow_enum",
    PartialOrd = "feature_allow_slow_enum",
    Ord = "feature_allow_slow_enum",
    Eq
)]
pub enum CompErrorKind<'a> {
    Other(String),
    MultipleSourceSharing(Vec<Connection<'a>>),
    MixedValidity {
        validities: Vec<(gadgets::Sharing<'a>, timed_gadgets::Validity, Vec<Latency>)>,
        subgadget: timed_gadgets::Name<'a>,
        #[derivative(PartialOrd = "ignore")]
        #[derivative(Ord = "ignore")]
        #[derivative(PartialEq = "ignore")]
        input_connections: HashMap<gadgets::Sharing<'a>, timed_gadgets::TConnection<'a>>,
        #[derivative(PartialOrd = "ignore")]
        #[derivative(Ord = "ignore")]
        #[derivative(PartialEq = "ignore")]
        gadgets_validity: HashMap<timed_gadgets::Name<'a>, timed_gadgets::Validity>,
    },
    MissingSourceSharing {
        subgadget: GName<'a>,
        sharing: gadgets::Sharing<'a>,
        #[derivative(PartialOrd = "ignore")]
        #[derivative(Ord = "ignore")]
        #[derivative(PartialEq = "ignore")]
        nets: &'a [yosys::BitVal],
    },
    MissingSourceSharingOut(gadgets::Sharing<'a>),
    MultipleUseRandom {
        random: (gadgets::Random<'a>, gadgets::Latency),
        uses: Vec<(
            (timed_gadgets::Name<'a>, gadgets::Random<'a>),
            Vec<(RndConnection<'a>, gadgets::Latency)>,
        )>,
    },
    InvalidPortDirection {
        attr: crate::netlist::WireAttrs,
        #[derivative(PartialOrd = "ignore")]
        #[derivative(Ord = "ignore")]
        #[derivative(PartialEq = "ignore")]
        direction: yosys::PortDirection,
    },
    WrongAnnotation(
        String,
        #[derivative(PartialOrd = "ignore")]
        #[derivative(Ord = "ignore")]
        #[derivative(PartialEq = "ignore")]
        yosys::AttributeVal,
    ),
    MissingAnnotation(String),
    WrongWireWidth(u32, u32),
    NoOutput,
    LateOutput(Latency, String, gadgets::Sharing<'a>),
    BadShareUse(Connection<'a>, String, String, usize),
    InvalidRandom(
        Vec<timed_gadgets::TRandom<'a>>,
        timed_gadgets::Name<'a>,
        gadgets::Random<'a>,
        #[derivative(PartialOrd = "ignore")]
        #[derivative(Ord = "ignore")]
        #[derivative(PartialEq = "ignore")]
        yosys::BitVal,
    ),
    OutputNotValid(Vec<(gadgets::Sharing<'a>, Latency)>),
    ExcedentaryOutput(Vec<(gadgets::Sharing<'a>, Latency)>),
    ConstantShare(String, gadgets::Sharing<'a>, u32),
    Vcd,
}

pub struct ASrc<'a>(pub &'a HashMap<String, yosys::AttributeVal>);
impl<'a> fmt::Display for ASrc<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0.get("src") {
            Some(yosys::AttributeVal::S(src)) => write!(f, "{}", src),
            _ => write!(f, "(Unknown)"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompErrors<'a>(Vec<CompError<'a>>);

impl<'a> CompErrors<'a> {
    pub fn new(mut errors: Vec<CompError<'a>>) -> Self {
        errors.sort_unstable();
        Self(errors)
    }
}

impl<'a> From<CompError<'a>> for CompErrors<'a> {
    fn from(x: CompError<'a>) -> Self {
        Self(vec![x])
    }
}

impl<'a> CompError<'a> {
    pub fn ref_nw(module: &yosys::Module, kind: CompErrorKind<'a>) -> Self {
        Self {
            module: Some(module.clone()),
            net: None,
            kind,
        }
    }
    pub fn ref_sn(module: &yosys::Module, netname: &str, kind: CompErrorKind<'a>) -> Self {
        Self {
            module: Some(module.clone()),
            net: Some(module.netnames[netname].clone()),
            kind,
        }
    }
    fn netname2name(&self) -> &str {
        self.module
            .as_ref()
            .unwrap()
            .netnames
            .iter()
            .filter(|(_, netname)| Some(*netname) == self.net.as_ref())
            .map(|(name, _)| name)
            .next()
            .unwrap()
    }
    fn fmt_net(&self, net: yosys::BitVal) -> (&str, usize) {
        self.module
            .as_ref()
            .unwrap()
            .netnames
            .iter()
            .filter_map(|(s, netname)| {
                netname
                    .bits
                    .iter()
                    .position(|x| x == &net)
                    .map(|p| (s.as_str(), p))
            })
            .next()
            .unwrap()
    }
    pub fn no_mod(kind: CompErrorKind<'a>) -> Self {
        Self {
            module: None,
            net: None,
            kind,
        }
    }
    pub fn missing_annotation(module: &yosys::Module, netname: &str, attr: &str) -> Self {
        Self::ref_sn(
            module,
            netname,
            CompErrorKind::MissingAnnotation(attr.to_owned()),
        )
    }
}

impl<'a> fmt::Display for CompError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(m) = self.module.as_ref() {
            write!(f, "fullverif: Error in module at {}", ASrc(&m.attributes),)?;
            if let Some(n) = self.net.as_ref() {
                writeln!(
                    f,
                    "for net {} (declared at {}).",
                    self.netname2name(),
                    ASrc(&n.attributes),
                )?;
            } else {
                writeln!(f)?;
            }
        }
        match &self.kind {
            CompErrorKind::Other(err) => {
                writeln!(f, "{}", err)?;
            }
            CompErrorKind::MultipleSourceSharing(sources) => {
                writeln!(f, "Multiple sources for net:")?;
                for source in sources.iter() {
                    let src_a = match source {
                        Connection::GadgetOutput { gadget_name, .. } => {
                            ASrc(&self.module.as_ref().unwrap().cells[*gadget_name].attributes)
                        }
                        Connection::Input(sharing) => ASrc(
                            &self.module.as_ref().unwrap().netnames[sharing.port_name].attributes,
                        ),
                    };
                    writeln!(f, "{} (at line {})", source, src_a)?;
                }
            }
            CompErrorKind::MixedValidity {
                validities,
                subgadget,
                input_connections,
                gadgets_validity,
            } => {
                writeln!(
                    f,
                    "Mixing valid and invalid inputs for sub-gadget '{}' at {}, for cycle {}.",
                    subgadget.0,
                    ASrc(&self.module.as_ref().unwrap().cells[subgadget.0].attributes),
                    subgadget.1
                )?;
                for (sharing, validity, valid_cycles) in validities.iter() {
                    writeln!(f, "\tInput sharing {} is {:?}.", sharing, validity)?;
                    writeln!(f, "\t\tNote: connection: {:?}", input_connections[sharing])?;
                    //if validity == &timed_gadgets::Validity::Invalid {
                    writeln!(f, "\t\tNote: input valid at cycle(s) {:?}.", valid_cycles)?;
                    //}
                }
                let mut valid_cycles = HashMap::new();
                for ((name, cycle), val) in gadgets_validity.iter() {
                    if val == &timed_gadgets::Validity::Valid {
                        valid_cycles
                            .entry(*name)
                            .or_insert_with(Vec::new)
                            .push(cycle);
                    }
                }
                for (name, val_cycles) in valid_cycles.iter_mut() {
                    val_cycles.sort_unstable();
                    writeln!(
                        f,
                        "\tNote: Gadget {} valid at cycles {:?}.",
                        name, val_cycles
                    )?;
                }
            }
            CompErrorKind::MissingSourceSharing {
                subgadget,
                sharing,
                nets,
            } => {
                writeln!(
                    f,
                    "Cannot find source for input {} of sub-gadget {} (it is likely not recognized as an output sharing of a gadget).",
                    sharing, subgadget
                )?;
                for (i, net) in nets.iter().enumerate() {
                    let (src_n, src_idx) = self.fmt_net(*net);
                    writeln!(
                        f,
                        "\tNote: {}[{}] is assigned to {}[{}].",
                        sharing, i, src_n, src_idx
                    )?;
                }
            }
            CompErrorKind::MissingSourceSharingOut(sharing) => {
                writeln!(f, "Cannot find source for output sharing {}.", sharing)?;
            }
            CompErrorKind::MultipleUseRandom { random, uses } => {
                writeln!(
                    f,
                    "Multiple use of random {} at cycle {}:",
                    random.0, random.1
                )?;
                for ((sg, port), trace) in uses.iter() {
                    writeln!(f, "\tSubgadget {:?}, port {}. Trace: {:?}", sg, port, trace)?;
                }
            }
            CompErrorKind::InvalidPortDirection { attr, direction } => {
                writeln!(
                    f,
                    "Invalid port direction {:?} for attribute {:?}",
                    direction, attr
                )?;
                writeln!(
                    f,
                    "\tNote: Randoms must be inputs, sharings must be inputs or outputs."
                )?;
            }
            CompErrorKind::WrongAnnotation(attr, attr_val) => {
                writeln!(f, "Invalid value for attribute {}: {:?}.", attr, attr_val)?;
            }
            CompErrorKind::MissingAnnotation(attr) => {
                writeln!(f, "Missing attribute {}.", attr)?;
            }
            CompErrorKind::WrongWireWidth(actual, expected) => {
                writeln!(
                    f,
                    "Wire has incorrect size: {} (expected {}).",
                    actual, expected
                )?;
            }
            CompErrorKind::NoOutput => {
                writeln!(f, "Gadget has no output sharing (at least 1 is required).",)?;
            }
            CompErrorKind::LateOutput(lateness, sg, output) => {
                writeln!(
                    f,
                    "Output {} of subgadget {} is too late by {} cycle(s).",
                    output, sg, lateness
                )?;
                writeln!(f, "The security of late computations cannot be checked.")?;
            }
            CompErrorKind::BadShareUse(connection, sg, port, offset) => {
                writeln!(
                    f,
                    "Sharing {} used as non-share connection {}.{}[{}].",
                    connection, sg, port, offset
                )?;
            }
            CompErrorKind::InvalidRandom(conns, sg_name, rnd_name, bitval) => {
                write!(f, "Use of non-random value as randomness for {:?} input to gadget {:?}:\n\t{:?} (bit {}).\n", rnd_name, sg_name, conns, DBitVal(bitval, self.module.as_ref().unwrap()))?;
            }
            CompErrorKind::OutputNotValid(outputs) => {
                writeln!(f, "The following outputs are not valid (although annotation specifies they should be valid):")?;
                for (sharing, cycle) in outputs {
                    writeln!(f, "\tOutput {} at cycle {}", sharing, cycle)?;
                }
            }
            CompErrorKind::ExcedentaryOutput(outputs) => {
                writeln!(f, "The following outputs are valid (although annotation specifies they should not be valid):")?;
                for (sharing, cycle) in outputs {
                    writeln!(f, "\tOutput {} at cycle {}", sharing, cycle)?;
                }
            }
            CompErrorKind::ConstantShare(sub_gadget, sharing, index) => {
                write!(
                    f,
                    "Bit {} of sharing {} of sub-gadget {} is a constant value, while \
                     it should be part of a valid sharing (either output of a gadget or \
                     input sharing.\n\tHint: if you need constants in the algorithm, \
                     use a gadget that shares a constant.\n",
                    index, sharing, sub_gadget
                )?;
            }
            CompErrorKind::Vcd => {
                writeln!(f, "Error in the format of the vcd file.")?;
            }
        }
        Ok(())
    }
}

impl<'a> fmt::Display for gadgets::Random<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}[{}]", self.port_name, self.offset)
    }
}

impl<'a> fmt::Display for gadget_internals::RndConnection<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            gadget_internals::RndConnection::Port(rnd) => write!(f, "port:{}", rnd),
            gadget_internals::RndConnection::Gate((gn, goff)) => write!(f, "gate:{}[{}]", gn, goff),
            gadget_internals::RndConnection::Invalid(bit) => {
                write!(f, "invalid(non-random, bit {:?})", bit)
            }
        }
    }
}

impl<'a> fmt::Display for CompErrors<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let n_max = 100;
        for e in self.0.iter().take(n_max) {
            write!(f, "{}", e)?;
        }
        if self.0.len() > n_max {
            writeln!(f, "\t\t[...]")?;
        }
        writeln!(f, "fullverif: {} errors found.", self.0.len())?;
        Ok(())
    }
}

impl<'a> fmt::Display for Connection<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Connection::GadgetOutput {
                gadget_name,
                output,
            } => write!(f, "Ouput {} of gadget {}", output, gadget_name),
            Connection::Input(sharing) => write!(f, "Input {} of current gadget", sharing),
        }
    }
}

impl<'a> fmt::Display for gadgets::Sharing<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} (bits [{}*d+:d])", self.port_name, self.pos)
    }
}

impl<'a> std::error::Error for CompError<'a> {}
impl<'a> std::error::Error for CompErrors<'a> {}

#[derive(Debug, Clone)]
pub struct DBitVal<'a>(pub &'a yosys::BitVal, pub &'a yosys::Module);

impl<'a> fmt::Display for DBitVal<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            yosys::BitVal::S(yosys::SpecialBit::_0) => write!(f, "'0'"),
            yosys::BitVal::S(yosys::SpecialBit::_1) => write!(f, "'1'"),
            yosys::BitVal::S(yosys::SpecialBit::X) => write!(f, "'X'"),
            yosys::BitVal::S(yosys::SpecialBit::Z) => write!(f, "'Z'"),
            yosys::BitVal::N(_) => {
                let mut names = netlist::get_names(self.1, *self.0).collect::<Vec<_>>();
                if names
                    .iter()
                    .any(|(wirename, _)| !wirename.contains("techmap"))
                {
                    names.retain(|(wirename, _)| !wirename.contains("techmap"));
                }
                names.sort_unstable_by_key(|(wn, _)| wn.len());
                match names.len() {
                    0 => panic!("Invalid bitval {:?}", self.0),
                    1 => write!(f, "{}[{}]", names[0].0, names[0].1),
                    l => {
                        write!(f, "{}[{}] (aka ", names[0].0, names[0].1)?;
                        for (name, offset) in names[1..std::cmp::min(5, l)].iter() {
                            write!(f, "{}[{}], ", name, offset)?;
                        }
                        if l >= 5 {
                            write!(f, "...)")
                        } else {
                            write!(f, ")")
                        }
                    }
                }
            }
        }
    }
}
