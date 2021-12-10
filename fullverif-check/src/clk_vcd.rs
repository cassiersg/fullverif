//! Analysis of vcd files as a series of state, for each clock cycle.

use crate::error::{CompError, CompErrorKind};
use std::borrow::Borrow;
use std::collections::HashMap;

/// State of a circuit at one clock cycle.
pub type State = HashMap<vcd::IdCode, VarState>;

/// State of a variable at one clock cycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VarState {
    Scalar(vcd::Value),
    Vector(Vec<vcd::Value>),
    Uninit,
}

impl VarState {
    pub fn to_bool(&self) -> Option<bool> {
        match self {
            VarState::Scalar(vcd::Value::V0) => Some(false),
            VarState::Scalar(vcd::Value::V1) => Some(true),
            _ => None,
        }
    }
}

/// Id of a variable (for lookup into State)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VarId(vcd::IdCode);

/// States of a circuit over time.
#[derive(Debug)]
pub struct VcdStates {
    header: vcd::Header,
    states: Vec<State>,
    cache_ids: std::cell::RefCell<CacheNameIds>,
}

/// Cache for lookups of path -> ids.
/// (to improve performance, since vcd::find_var uses linear probing)
#[derive(Debug, Default)]
struct CacheNameIds {
    id: usize,
    scopes: HashMap<String, CacheNameIds>,
}
impl CacheNameIds {
    fn new(id: usize) -> Self {
        Self {
            id,
            scopes: HashMap::new(),
        }
    }
}

impl VcdStates {
    /// Create VcdStates from a reader of a vcd file and the path of the clock signal.
    pub fn new<'a>(
        r: &mut impl std::io::Read,
        clock: &[impl Borrow<str>],
    ) -> Result<Self, CompError<'a>> {
        let mut parser = vcd::Parser::new(r);
        let vcd_error = CompError::no_mod(CompErrorKind::Vcd);
        let header = parser.parse_header().map_err(|_| vcd_error.clone())?;
        let clock = header
            .find_var(clock)
            .ok_or_else(|| {
                CompError::no_mod(CompErrorKind::Other(format!(
                    "Error: Did not find clock {:?} in vcd file.",
                    clock.join(".")
                )))
            })?
            .code;
        let vars = list_vars(&header);
        let states = clocked_states(
            &vars,
            clock,
            parser.map(|cmd| cmd.map_err(|_| vcd_error.clone())),
        )?;
        let cache_ids = std::cell::RefCell::new(CacheNameIds::default());
        Ok(Self {
            header,
            states,
            cache_ids,
        })
    }

    /// VarId from the path (list of strings) of a variable
    pub fn get_var_id<'a>(&self, path: &[impl Borrow<str>]) -> Result<VarId, CompError<'a>> {
        let mut cache = self.cache_ids.borrow_mut();
        let mut dir: &mut CacheNameIds = &mut (*cache);
        let mut scope: &[vcd::ScopeItem] = &self.header.items;
        for (path_part, name) in path.iter().enumerate() {
            let n = name.borrow();
            if dir.scopes.contains_key(n) {
                dir = dir.scopes.get_mut(n).unwrap();
                match &scope[dir.id] {
                    vcd::ScopeItem::Scope(s) => {
                        scope = &s.children;
                    }
                    vcd::ScopeItem::Var(v) => {
                        if path_part == path.len() - 1 {
                            return Ok(VarId(v.code));
                        } else {
                            // error
                            break;
                        }
                    }
                }
            } else {
                fn scope_id(s: &vcd::ScopeItem) -> &str {
                    let res = match s {
                        vcd::ScopeItem::Var(v) => &v.reference,
                        vcd::ScopeItem::Scope(s) => &s.identifier,
                    };
                    // Remove leading backslash, in case the vcd is encoded using the "escaped
                    // identifier" syntax of verilog.
                    res.strip_prefix("\\").unwrap_or(res)
                }
                match scope.iter().enumerate().find(|(_, s)| scope_id(s) == n) {
                    Some((i, s)) => {
                        dir = dir
                            .scopes
                            .entry(scope_id(s).to_owned())
                            .or_insert(CacheNameIds::new(i));
                        if let vcd::ScopeItem::Scope(s) = s {
                            scope = &s.children;
                        } else {
                            match &scope[dir.id] {
                                vcd::ScopeItem::Scope(s) => {
                                    scope = &s.children;
                                }
                                vcd::ScopeItem::Var(v) => {
                                    if path_part == path.len() - 1 {
                                        return Ok(VarId(v.code));
                                    } else {
                                        // error
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    None => {
                        break;
                    }
                }
            }
        }
        return Err(CompError {
            module: None,
            net: None,
            kind: CompErrorKind::Other(format!(
                "Error: Did not find signal {} in vcd file.",
                path.join(".")
            )),
        }
        .into());
    }

    /// State of a variable. Returns None if the cycle is too large compared to what was in the vcd.
    pub fn get_var(&self, var: VarId, cycle: usize) -> Option<&VarState> {
        trace!("cycle: {}, n_cycles: {}", cycle, self.states.len());
        self.states.get(cycle).map(|state| &state[&var.0])
    }

    /// State of a wire in a vector variable. Returns None if the cycle is too large compared to
    /// what was in the vcd.
    pub fn get_var_idx(&self, var: VarId, cycle: usize, offset: usize) -> Option<VarState> {
        self.get_var(var, cycle).map(|state| match state {
            res @ VarState::Scalar(_) => {
                assert_eq!(offset, 0);
                res.clone()
            }
            res @ VarState::Uninit => res.clone(),
            VarState::Vector(values) => VarState::Scalar(values[offset]),
        })
    }

    /// Number of clock cycles in the vcd file.
    pub fn len(&self) -> usize {
        self.states.len()
    }
}

// FIXME: could we replace the Vec<String> with a VarId for better efficiency ?
/// Records the path and the results of all the queries.
pub type StateLookups = HashMap<(Vec<String>, usize, usize), Option<VarState>>;

/// Query the control signals in a module.
/// Adds the following features on top of VcdStates:
/// * working in a submodule (i.e. prepends a prefix to all path queries)
/// * working from a cycle offset.
/// * recording all the queries (and their results)
#[derive(Debug)]
pub struct ModuleControls<'a> {
    vcd_states: &'a VcdStates,
    offset: usize,
    root_module: Vec<String>,
    accessed: StateLookups,
}

impl<'a> ModuleControls<'a> {
    pub fn new(vcd_states: &'a VcdStates, root_module: Vec<String>, offset: usize) -> Self {
        Self {
            vcd_states,
            offset,
            root_module,
            accessed: HashMap::new(),
        }
    }

    /// Create a ModulesControls for the given root_module, with cycle 0 set to the first cycle
    /// where tne enable signal is asserted.
    /// The enable signal and root_module paths start at the vcd root.
    pub fn from_enable<'b>(
        vcd_states: &'a VcdStates,
        root_module: Vec<String>,
        enable: &[impl Borrow<str>],
    ) -> Result<Self, CompError<'b>> {
        let enable_code = vcd_states.get_var_id(enable)?;
        let offset = (0..vcd_states.len())
            .find(|i| {
                vcd_states.get_var(enable_code, *i).unwrap() == &VarState::Scalar(vcd::Value::V1)
            })
            .ok_or_else(|| CompError {
                module: None,
                net: None,
                kind: CompErrorKind::Other(format!(
                    "Error: Enable signal {:?} never asserted.",
                    enable.join(".")
                )),
            })?;
        debug!("ModuleControls offset: {}", offset);
        Ok(Self::new(vcd_states, root_module, offset))
    }

    /// Create a fresh ModuleControls, incrementing the cycle offset by time_offset from the
    /// current offset and selecting a sub-module path from the current one.
    /// The StateLookups state of the new ModuleControls is empty.
    pub fn submodule(&self, module: String, time_offset: usize) -> Self {
        let mut path = self.root_module.clone();
        path.push(module);
        Self {
            vcd_states: self.vcd_states,
            offset: self.offset + time_offset,
            root_module: path,
            accessed: StateLookups::new(),
        }
    }

    /// Lookup the value of the wire path[idx] at the given cycle.
    /// Returns None when the cycle to be looked up is after the end of the vcd file.
    pub fn lookup<'b>(
        &mut self,
        path: Vec<String>,
        cycle: usize,
        idx: usize,
    ) -> Result<Option<&VarState>, CompError<'b>> {
        let mut p: Vec<String> = self.root_module.clone();
        p.extend(path.iter().map(|s| s.to_owned()));
        let var_id = self.vcd_states.get_var_id(&p)?;
        let vcd_states = &self.vcd_states;
        let accessed = &mut self.accessed;
        let offset = self.offset;
        Ok(accessed
            .entry((path, cycle, idx))
            .or_insert_with(|| vcd_states.get_var_idx(var_id, offset + cycle, idx))
            .as_ref())
    }

    /// Returns the list of the lookups.
    pub fn lookups(self) -> StateLookups {
        self.accessed
    }

    /// Number of cycles from the start of the module to the end of the vcd.
    pub fn len(&self) -> usize {
        self.vcd_states.len() - self.offset
    }
}

/// Maps the state of a vector signal from the vcd (truncated, BE) to the representation used in
/// the states (not trucated, LE).
fn pad_vec_and_reverse(mut vec: Vec<vcd::Value>, size: u32) -> Vec<vcd::Value> {
    // We need to reverse order of bits since last one in binary writing is at offset 0.
    // Then we pad since leading '0', 'x' or 'z' are not always written.
    let padding_value = if vec[0] == vcd::Value::V1 {
        vcd::Value::V0
    } else {
        vec[0]
    };
    vec.reverse();
    vec.extend(std::iter::repeat(padding_value).take((size as usize) - vec.len()));
    vec
}

/// Computes the state from the vcd reader, the clock and the list of variables.
fn clocked_states<'a>(
    vars: &HashMap<vcd::IdCode, vcd::Var>,
    clock: vcd::IdCode,
    commands: impl Iterator<Item = Result<vcd::Command, CompError<'a>>>,
) -> Result<Vec<State>, CompError<'a>> {
    let mut states = Vec::new();
    let mut current_state = vars
        .keys()
        .map(|code| (*code, VarState::Uninit))
        .collect::<HashMap<_, _>>();
    let mut previous_state = current_state.clone();
    let mut clk_state = vcd::Value::X;
    let mut started = false;
    for command in commands {
        match command? {
            vcd::Command::ChangeScalar(id_code, value) => {
                if id_code == clock {
                    match value {
                        vcd::Value::V1 if clk_state == vcd::Value::V0 => {
                            states.push(previous_state.clone());
                            clk_state = vcd::Value::V1;
                            started = true;
                        }
                        vcd::Value::V0 | vcd::Value::V1 => {
                            clk_state = value;
                            started = true;
                        }
                        vcd::Value::X | vcd::Value::Z => {
                            if started {
                                return Err(CompError::no_mod(CompErrorKind::Other(format!(
                                    "Invalid value for the clock: {:?} (at cycle >= {}).",
                                    value,
                                    states.len()
                                ))));
                            }
                        }
                    }
                }
                current_state.insert(id_code, VarState::Scalar(value));
            }
            vcd::Command::ChangeVector(id_code, value) => {
                current_state.insert(
                    id_code,
                    VarState::Vector(pad_vec_and_reverse(value, vars[&id_code].size)),
                );
            }
            vcd::Command::Timestamp(_) => {
                previous_state = current_state.clone();
            }
            _ => {}
        }
    }
    states.push(current_state);
    Ok(states)
}

/// List the variables in the vcd.
fn list_vars(header: &vcd::Header) -> HashMap<vcd::IdCode, vcd::Var> {
    let mut res = HashMap::new();
    let mut remaining_items = header.items.iter().collect::<Vec<_>>();
    while let Some(scope_item) = remaining_items.pop() {
        match scope_item {
            vcd::ScopeItem::Scope(scope) => {
                remaining_items.extend(scope.children.iter());
            }
            vcd::ScopeItem::Var(var) => {
                res.insert(var.code, var.clone());
            }
        }
    }
    res
}
