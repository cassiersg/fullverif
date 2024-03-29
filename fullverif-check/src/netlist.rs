//! Parsing and basing analysis of yosys JSON netlist:
//! fullverif attributes parsing and misc functions.

use crate::error::{CompError, CompErrorKind};
use crate::gadgets::{self, Latency};
use itertools::Itertools;
use std::convert::TryInto;
use yosys_netlist_json as yosys;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RndLatencies {
    Attr(Vec<Latency>),
    Wire { wire_name: String, offset: i32 },
}

/// Return the attribute `attr` on the net `netname` in `module` as a string.
/// If the attribute is not present, return None.
/// If it has not the correct type, return an Err.
fn get_str_attr<'a>(
    module: &'a yosys::Module,
    netname: &str,
    attr: &str,
) -> Result<Option<&'a str>, CompError<'a>> {
    if let Some(attr_v) = module.netnames[netname].attributes.get(attr) {
        match attr_v {
            yosys::AttributeVal::S(x) => Ok(Some(x)),
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

/// Convert an attribute to an u32 if possible
fn attr2int(attr: &yosys::AttributeVal) -> Result<u32, ()> {
    match attr {
        yosys::AttributeVal::N(x) if TryInto::<u32>::try_into(*x).is_ok() => {
            Ok(TryInto::<u32>::try_into(*x).unwrap())
        }
        yosys::AttributeVal::S(s) if s.len() <= 32 && s.chars().all(|x| x == '0' || x == '1') => {
            Ok(s.chars()
                .rev()
                .enumerate()
                .map(|(i, c)| match c {
                    '0' => 0,
                    '1' => 1 << i,
                    _ => unreachable!(),
                })
                .sum())
        }
        _ => Err(()),
    }
}

/// Return the attribute `attr` on the net `netname` in `module` as an integer.
/// If the attribute is not present, return None.
/// If it has not the correct type (or overflows), return an Err.
fn get_int_attr<'a>(
    module: &'a yosys::Module,
    netname: &str,
    attr: &str,
) -> Result<Option<i32>, CompError<'a>> {
    if let Some(attr_v) = module.netnames[netname].attributes.get(attr) {
        match attr2int(attr_v) {
            Ok(x) => Ok(Some(x as i32)),
            Err(()) => Err(CompError::ref_sn(
                module,
                netname,
                CompErrorKind::WrongAnnotation(attr.to_owned(), attr_v.clone()),
            )),
        }
    } else {
        Ok(None)
    }
}

fn get_int_attr_pos<'a>(
    module: &'a yosys::Module,
    netname: &str,
    attr: &str,
) -> Result<Option<u32>, CompError<'a>> {
    get_int_attr(module, netname, attr).and_then(|v| {
        v.map(|n| {
            if n < 0 {
                Err(CompError::ref_sn(
                    module,
                    netname,
                    CompErrorKind::WrongAnnotation(
                        attr.to_owned(),
                        yosys::AttributeVal::N(n as usize),
                    ),
                ))
            } else {
                Ok(n as u32)
            }
        })
        .transpose()
    })
}

/// See get_int_attr but returns Err if the attribute is not present.
fn get_int_attr_needed<'a>(
    module: &'a yosys::Module,
    netname: &str,
    attr: &str,
) -> Result<i32, CompError<'a>> {
    get_int_attr(module, netname, attr)?
        .ok_or_else(|| CompError::missing_annotation(module, netname, attr))
}

/// Gen the attribute `attr` on netname in module.
/// The attribute should be an arbitrary-length bit vector (i.e., any int).
/// We return the result as a LE bit Vec<bool>
fn get_bitstring_attr<'a>(
    module: &'a yosys::Module,
    netname: &str,
    attr: &str,
) -> Result<Option<Vec<bool>>, CompError<'a>> {
    if let Some(attr_v) = module.netnames[netname].attributes.get(attr) {
        // We have to handle the string attribute case since this is how
        // yosys encodes ints with more than 32 bits.
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

/// Fullverif type for a wire
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WireAttrs {
    Sharing {
        latencies: gadgets::Latencies,
        count: u32,
    },
    Random(Vec<Option<RndLatencies>>),
    Control,
    Clock,
}

/// Fullverif security property for a module gadget.
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
            GadgetProp::Mux | GadgetProp::Affine | GadgetProp::PINI => true,
            _ => false,
        }
    }
    pub fn is_affine(&self) -> bool {
        match self {
            GadgetProp::Mux | GadgetProp::Affine => true,
            _ => false,
        }
    }
}

/// Fullverif strategy for proving security of a gadget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GadgetStrat {
    Assumed,
    CompositeProp,
    Isolate,
}

/// Get values for the latency annotation of a port.
fn get_latencies<'a>(
    module: &'a yosys::Module,
    netname: &str,
    attr_latency: &str,
    attr_latencies: &str,
    attr_latencies_wire: &str,
    attr_lat_sig_offset: &str,
) -> Result<RndLatencies, CompError<'a>> {
    let latency = get_int_attr_pos(module, netname, attr_latency)?;
    let latencies = get_bitstring_attr(module, netname, attr_latencies)?;
    let latencies_wire = get_str_attr(module, netname, attr_latencies_wire)?;
    let attrs_present = [
        (latency.is_some(), attr_latency),
        (latencies.is_some(), attr_latencies),
        (latencies_wire.is_some(), attr_latencies_wire),
    ];
    let present_attrs = attrs_present
        .iter()
        .filter(|(o, _)| *o)
        .map(|(_, a)| a)
        .collect::<Vec<_>>();
    if present_attrs.len() >= 2 {
        return Err(CompError::ref_sn(
            module,
            netname,
            CompErrorKind::ConflictingAnnotations(
                present_attrs[0].to_string(),
                present_attrs[1].to_string(),
            ),
        ));
    }
    let latencies = if let Some(latencies_wire) = latencies_wire {
        let offset = get_int_attr(module, netname, attr_lat_sig_offset)?
            .ok_or_else(|| CompError::missing_annotation(module, netname, attr_lat_sig_offset))?;
        RndLatencies::Wire {
            wire_name: latencies_wire.to_string(),
            offset,
        }
    } else if let Some(l) = latencies {
        RndLatencies::Attr(
            l.into_iter()
                .positions(|x| x)
                .map(|x| x.try_into().expect("negative latency"))
                .collect(),
        )
    } else if let Some(l) = latency {
        RndLatencies::Attr(vec![l.try_into().expect("negative latency")])
    } else {
        return Err(CompError::missing_annotation(module, netname, attr_latency));
    };
    return Ok(latencies);
}

/// Get the type of a port.
pub fn net_attributes<'a>(
    module: &'a yosys::Module,
    netname: &str,
) -> Result<WireAttrs, CompError<'a>> {
    let net = &module.netnames[netname];
    let fv_type = net.attributes.get("fv_type");
    let fv_count = get_int_attr_pos(module, netname, "fv_count")?;
    match fv_type {
        Some(yosys::AttributeVal::S(kind)) if kind == "sharing" => {
            let latencies = if let RndLatencies::Attr(latencies) = get_latencies(
                module,
                netname,
                "fv_latency",
                "fv_latencies",
                "__DO_NOT_USE_",
                "__DO_NOT_USE",
            )? {
                latencies
            } else {
                return Err(CompError::ref_sn(
                    module,
                    netname,
                    CompErrorKind::MissingAnnotation("fv_latency".to_owned()),
                ));
            };
            Ok(WireAttrs::Sharing {
                latencies,
                count: fv_count.unwrap_or(1),
            })
        }
        Some(yosys::AttributeVal::S(kind)) if kind == "random" => {
            let fv_count = fv_count
                .ok_or_else(|| CompError::missing_annotation(module, netname, "fv_count"))?;
            if fv_count == 0 {
                Ok(WireAttrs::Random(vec![None; net.bits.len()]))
            } else {
                let mut res = Vec::new();
                for i in 0..fv_count {
                    let n_bits =
                        get_int_attr_needed(module, netname, &format!("fv_rnd_count_{}", i))?;
                    let latencies = get_latencies(
                        module,
                        netname,
                        &format!("fv_rnd_lat_{}", i),
                        &format!("fv_rnd_lats_{}", i),
                        &format!("fv_en_{}", i),
                        &format!("fv_en_offset_{}", i),
                    )?;
                    for _ in 0..n_bits {
                        res.push(Some(latencies.clone()));
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

/// Get the security property annotation of a module.
/// Returns None if not specified, Err if invalid.
pub fn module_prop<'a>(module: &'a yosys::Module) -> Result<Option<GadgetProp>, CompError<'a>> {
    module
        .attributes
        .get("fv_prop")
        .map(|prop| match prop {
            yosys::AttributeVal::S(attr) if attr == "_mux" => Ok(GadgetProp::Mux),
            yosys::AttributeVal::S(attr) if attr == "affine" => Ok(GadgetProp::Affine),
            yosys::AttributeVal::S(attr) if attr == "NI" => Ok(GadgetProp::NI),
            yosys::AttributeVal::S(attr) if attr == "PINI" => Ok(GadgetProp::PINI),
            yosys::AttributeVal::S(attr) if attr == "SNI" => Ok(GadgetProp::SNI),
            attr => Err(CompError {
                module: Some(module),
                net: None,
                kind: CompErrorKind::WrongAnnotation("fv_prop".to_owned(), attr.clone()),
            }),
        })
        .transpose()
}

/// Get the security proof strategy for the module.
/// Returns Err if the annotation is invalid of missing.
pub fn module_strat<'a>(module: &'a yosys::Module) -> Result<GadgetStrat, CompError<'a>> {
    match module.attributes.get("fv_strat").ok_or_else(|| {
        CompError::ref_nw(
            module,
            CompErrorKind::MissingAnnotation("fv_strat".to_owned()),
        )
    })? {
        yosys::AttributeVal::S(attr) if attr == "assumed" => Ok(GadgetStrat::Assumed),
        yosys::AttributeVal::S(attr) if attr == "composite" => Ok(GadgetStrat::CompositeProp),
        yosys::AttributeVal::S(attr) if attr == "isolate" => Ok(GadgetStrat::Isolate),
        attr => Err(CompError::ref_nw(
            module,
            CompErrorKind::WrongAnnotation("fv_strat".to_owned(), attr.clone()),
        )),
    }
}

/// Get the masking number of shares of a module.
/// Returns Err if the annotation is invalid of missing.
pub fn module_order<'a>(module: &'a yosys::Module) -> Result<u32, CompError<'a>> {
    let attr = module.attributes.get("fv_order").ok_or_else(|| {
        CompError::ref_nw(
            module,
            CompErrorKind::MissingAnnotation("fv_order".to_owned()),
        )
    })?;
    match attr2int(attr) {
        Ok(x) if x >= 1 => Ok(x as u32),
        _ => Err(CompError::ref_nw(
            module,
            CompErrorKind::WrongAnnotation("fv_order".to_owned(), attr.clone()),
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
