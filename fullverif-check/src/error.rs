//! Error types for the app.
//! CompError is the general error type, which as some generic attributes, and a CompErrorKind
//! attrivute.
//! CompErrorKind is an enum that conveys information about the type of error (and details).
//! CompErrors is an Error type containing multiple CompError. We use it to report multiple errors
//! to the user at once.

use std::fmt;

use crate::gadget_internals::Connection;
use crate::gadget_internals::{self, GName, RndConnection};
use crate::gadgets::{self, Latency};
use crate::netlist;
use crate::tg_graph;
use std::collections::HashMap;
use yosys_netlist_json as yosys;

pub type CResult<'a, T> = Result<T, CompErrors<'a>>;

#[derive(Debug, Clone, Derivative)]
#[derivative(PartialEq, PartialOrd, Ord, Eq)]
pub struct CompError<'a> {
    pub kind: CompErrorKind<'a>,
    #[derivative(PartialOrd = "ignore")]
    #[derivative(Ord = "ignore")]
    #[derivative(PartialEq = "ignore")]
    pub module: Option<&'a yosys::Module>,
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
            (tg_graph::Name<'a>, tg_graph::TRandom<'a>),
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
    ConflictingAnnotations(String, String),
    WrongWireWidth(u32, u32),
    NoOutput,
    EarlyOutput,
    LateOutput(Latency, String, gadgets::Sharing<'a>),
    BadShareUse(Connection<'a>, String, String, usize),
    InvalidRandom(
        Vec<tg_graph::TRndConnection<'a>>,
        tg_graph::Name<'a>,
        tg_graph::TRandom<'a>,
        #[derivative(PartialOrd = "ignore")]
        #[derivative(Ord = "ignore")]
        #[derivative(PartialEq = "ignore")]
        yosys::BitVal,
    ),
    OutputNotValid(Vec<(gadgets::Sharing<'a>, Latency)>),
    ExcedentaryOutput(Vec<(gadgets::Sharing<'a>, Latency)>),
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
pub struct CompErrors<'a>(pub Vec<CompError<'a>>);

impl<'a> CompErrors<'a> {
    pub fn new(mut errors: Vec<CompError<'a>>) -> Self {
        errors.sort_unstable();
        Self(errors)
    }
    pub fn result(errors: Vec<CompError<'a>>) -> CResult<'a, ()> {
        if errors.is_empty() {
            Ok(())
        } else {
            Err(Self::new(errors))
        }
    }
}

impl<'a> From<CompError<'a>> for CompErrors<'a> {
    fn from(x: CompError<'a>) -> Self {
        Self(vec![x])
    }
}

impl<'a> CompError<'a> {
    pub fn ref_nw(module: &'a yosys::Module, kind: CompErrorKind<'a>) -> Self {
        Self {
            module: Some(module),
            net: None,
            kind,
        }
    }
    pub fn ref_sn(module: &'a yosys::Module, netname: &str, kind: CompErrorKind<'a>) -> Self {
        Self {
            module: Some(module),
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
    pub fn missing_annotation(module: &'a yosys::Module, netname: &str, attr: &str) -> Self {
        Self::ref_sn(
            module,
            netname,
            CompErrorKind::MissingAnnotation(attr.to_owned()),
        )
    }
    pub fn other(module: &'a yosys::Module, netname: &str, err: &str) -> Self {
        Self::ref_sn(module, netname, CompErrorKind::Other(err.to_owned()))
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
                        Connection::GadgetOutput { gadget_name, .. } => ASrc(
                            &self.module.as_ref().unwrap().cells[*gadget_name.get()].attributes,
                        ),
                        Connection::Input(sharing) => ASrc(
                            &self.module.as_ref().unwrap().netnames[sharing.port_name].attributes,
                        ),
                    };
                    writeln!(f, "{} (at line {})", source, src_a)?;
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
                    writeln!(
                        f,
                        "\tSubgadget {:?}, random {:?}. Trace: {:?}",
                        sg, port, trace
                    )?;
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
            CompErrorKind::ConflictingAnnotations(attr1, attr2) => {
                writeln!(
                    f,
                    "Conflicting attributes {} and {}. (Only one of those may be provided.)",
                    attr1, attr2
                )?;
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
            CompErrorKind::EarlyOutput => {
                writeln!(
                    f,
                    "Gadget has valid output sharing before last input sharing or random.",
                )?;
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
            gadget_internals::RndConnection::Gate(gate) => write!(f, "gate:{}", gate),
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
