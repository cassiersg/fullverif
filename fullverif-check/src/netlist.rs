use crate::error::{CompError, CompErrorKind};
use crate::gadgets::{self, Latency};
use itertools::Itertools;
use std::convert::TryInto;
use yosys_netlist_json as yosys;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Net {
    wire_name: String,
    wire_index: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Sharing {
    gadget_index: usize,
    gadget_output: String,
}

fn get_int_attr<'a>(
    module: &yosys::Module,
    netname: &str,
    attr: &str,
) -> Result<Option<u32>, CompError<'a>> {
    if let Some(attr_v) = module.netnames[netname].attributes.get(attr) {
        match attr_v {
            yosys::AttributeVal::N(x) if TryInto::<Latency>::try_into(*x).is_ok() => {
                Ok(Some(*x as u32))
            }
            _ => Err(CompError::ref_sn(
                module,
                netname,
                CompErrorKind::WrongAnnotation(attr.to_owned(), attr_v.clone()),
            )),
        }
    } else {
        Ok(None)
    }
}

fn get_int_attr_needed<'a>(
    module: &yosys::Module,
    netname: &str,
    attr: &str,
) -> Result<u32, CompError<'a>> {
    get_int_attr(module, netname, attr)?
        .ok_or_else(|| CompError::missing_annotation(module, netname, attr))
}

fn get_bitstring_attr<'a>(
    module: &yosys::Module,
    netname: &str,
    attr: &str,
) -> Result<Option<Vec<bool>>, CompError<'a>> {
    if let Some(attr_v) = module.netnames[netname].attributes.get(attr) {
        match attr_v {
            yosys::AttributeVal::N(x) => {
                Ok(Some((0..32).map(|i| ((*x >> i) & 0x1) == 0x1).collect()))
            }
            yosys::AttributeVal::S(x) => Ok(Some(
                x.chars()
                    .rev()
                    .map(|c| match c {
                        '0' => Ok(false),
                        '1' => Ok(true),
                        _ => Err(CompError::ref_sn(
                            module,
                            netname,
                            CompErrorKind::WrongAnnotation(attr.to_owned(), attr_v.clone()),
                        )),
                    })
                    .collect::<Result<Vec<bool>, _>>()?,
            )),
        }
    } else {
        Ok(None)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WireAttrs {
    Sharing {
        latencies: gadgets::Latencies,
        count: u32,
    },
    Random(Vec<Option<gadgets::Latency>>),
    Control,
    Clock,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GadgetProp {
    Mux,
    Affine,
    NI,
    SNI,
    PINI,
}

impl GadgetProp {
    pub fn is_pini(&self) -> bool {
        match self {
            GadgetProp::Affine | GadgetProp::PINI => true,
            _ => false,
        }
    }
    pub fn is_affine(&self) -> bool {
        *self == GadgetProp::Affine
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GadgetStrat {
    Assumed,
    CompositeProp,
    Isolate,
}

pub fn net_attributes<'a>(
    module: &yosys::Module,
    netname: &str,
) -> Result<WireAttrs, CompError<'a>> {
    let net = &module.netnames[netname];
    let psim_type = net.attributes.get("psim_type");
    let psim_count = get_int_attr(module, netname, "psim_count")?;
    match psim_type {
        Some(yosys::AttributeVal::S(kind)) if kind == "sharing" => {
            let latency = get_int_attr(module, netname, "psim_latency")?;
            let latencies = get_bitstring_attr(module, netname, "psim_latencies")?;
            let latencies = if latency.is_some() && latencies.is_some() {
                return Err(CompError::ref_sn(
                    module,
                    netname,
                    CompErrorKind::ConflictingAnnotations("psim_latency", "psim_latencies"),
                ));
            } else if let Some(l) = latencies {
                l.into_iter()
                    .positions(|x| x)
                    .map(|x| x as Latency)
                    .collect()
            } else if let Some(l) = latency {
                vec![l]
            } else {
                return Err(CompError::missing_annotation(module, netname, "psim_count"));
            };
            Ok(WireAttrs::Sharing {
                latencies,
                count: psim_count.unwrap_or(1),
            })
        }
        Some(yosys::AttributeVal::S(kind)) if kind == "random" => {
            let psim_count = psim_count
                .ok_or_else(|| CompError::missing_annotation(module, netname, "psim_count"))?;
            if psim_count == 0 {
                Ok(WireAttrs::Random(vec![None; net.bits.len()]))
            } else {
                let mut res = Vec::new();
                for i in 0..psim_count {
                    let n_bits =
                        get_int_attr_needed(module, netname, &format!("psim_rnd_count_{}", i))?;
                    let latency =
                        get_int_attr_needed(module, netname, &format!("psim_rnd_lat_{}", i))?;
                    for _ in 0..n_bits {
                        res.push(Some(latency));
                    }
                }
                if res.len() != net.bits.len() {
                    return Err(CompError::ref_sn(module, netname, CompErrorKind::Other(format!("Random has not correct length true length: {}, expected: {}, attributes: {:?}",
                net.bits.len(),
                res.len(),
                net.attributes
                    ))));
                }
                Ok(WireAttrs::Random(res))
            }
        }
        Some(yosys::AttributeVal::S(kind)) if kind == "control" => Ok(WireAttrs::Control),
        Some(yosys::AttributeVal::S(kind)) if kind == "clock" => Ok(WireAttrs::Clock),
        _ => Err(CompError::ref_sn(
            module,
            netname,
            CompErrorKind::Other(format!(
                "Wrongly annotated port, attributes: {:?}",
                net.attributes
            )),
        )),
    }
}

pub fn module_prop<'a>(module: &yosys::Module) -> Result<Option<GadgetProp>, CompError<'a>> {
    module
        .attributes
        .get("psim_prop")
        .map(|prop| match prop {
            yosys::AttributeVal::S(attr) if attr == "_mux" => Ok(GadgetProp::Mux),
            yosys::AttributeVal::S(attr) if attr == "affine" => Ok(GadgetProp::Affine),
            yosys::AttributeVal::S(attr) if attr == "NI" => Ok(GadgetProp::NI),
            yosys::AttributeVal::S(attr) if attr == "PINI" => Ok(GadgetProp::PINI),
            yosys::AttributeVal::S(attr) if attr == "SNI" => Ok(GadgetProp::SNI),
            attr => Err(CompError {
                module: Some(module.clone()),
                net: None,
                kind: CompErrorKind::WrongAnnotation("psim_prop".to_owned(), attr.clone()),
            }),
        })
        .transpose()
}

pub fn module_strat<'a>(module: &yosys::Module) -> Result<GadgetStrat, CompError<'a>> {
    match module.attributes.get("psim_strat").ok_or_else(|| {
        CompError::ref_nw(
            module,
            CompErrorKind::MissingAnnotation("psim_strat".to_owned()),
        )
    })? {
        yosys::AttributeVal::S(attr) if attr == "assumed" => Ok(GadgetStrat::Assumed),
        yosys::AttributeVal::S(attr) if attr == "composite" => Ok(GadgetStrat::CompositeProp),
        yosys::AttributeVal::S(attr) if attr == "isolate" => Ok(GadgetStrat::Isolate),
        attr => Err(CompError::ref_nw(
            module,
            CompErrorKind::WrongAnnotation("psim_strat".to_owned(), attr.clone()),
        )),
    }
}

pub fn module_order<'a>(module: &yosys::Module) -> Result<u32, CompError<'a>> {
    match module.attributes.get("psim_order").ok_or_else(|| {
        CompError::ref_nw(
            module,
            CompErrorKind::MissingAnnotation("psim_order".to_owned()),
        )
    })? {
        yosys::AttributeVal::N(order) if *order >= 1 => Ok(*order as u32),
        attr => Err(CompError::ref_nw(
            module,
            CompErrorKind::WrongAnnotation("psim_order".to_owned(), attr.clone()),
        )),
    }
}

/// Get a name of a signal from its net id.
pub fn get_names(
    module: &yosys::Module,
    net: yosys::BitVal,
) -> impl Iterator<Item = (&str, usize)> {
    module.netnames.iter().flat_map(move |(name, netname)| {
        netname
            .bits
            .iter()
            .positions(move |bitval| *bitval == net)
            .map(move |i| (name.as_str(), i))
    })
}

/// Handling Yosys formatting: names starting with '$' are prefixed with '\' in vcd but not
/// in json.
/// There is also a difference between '\' escaping in vcd and json: '\' seems to be escaped in
/// both (as long as it is not at the start of the string, where it is not escaped in the vcd),
/// but the vcd parser does not unescape it...
pub fn format_name(name: &str) -> String {
    if name.starts_with('$') {
        format!("\\${}", name[1..].replace("\\", "\\\\"))
    } else {
        format!("{}{}", &name[0..1], name[1..].replace("\\", "\\\\"))
    }
}
