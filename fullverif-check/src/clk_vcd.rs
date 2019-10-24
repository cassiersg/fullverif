use crate::error::{CompError, CompErrorKind};
use std::borrow::Borrow;
use std::collections::HashMap;

pub type State = HashMap<vcd::IdCode, VarState>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VarState {
    Scalar(vcd::Value),
    Vector(Vec<vcd::Value>),
    Uninit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VarId(vcd::IdCode);

#[derive(Debug)]
pub struct VcdStates {
    header: vcd::Header,
    states: Vec<State>,
}

impl VcdStates {
    #[cfg_attr(feature = "flame_it", flame)]
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
                CompError::no_mod(CompErrorKind::Unknown(format!(
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
        Ok(Self { header, states })
    }
    pub fn get_var_id<'a>(&self, path: &[impl Borrow<str>]) -> Result<VarId, CompError<'a>> {
        Ok(VarId(
            self.header
                .find_var(path)
                .ok_or_else(|| CompError {
                    module: None,
                    net: None,
                    kind: CompErrorKind::Unknown(format!(
                        "Error: Did not find signal {} in vcd file.",
                        path.join(".")
                    )),
                })?
                .code,
        ))
    }
    pub fn get_var(&self, var: VarId, cycle: usize) -> Option<&VarState> {
        trace!("cycle: {}, n_cycles: {}", cycle, self.states.len());
        self.states.get(cycle).map(|state| &state[&var.0])
    }
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
    pub fn len(&self) -> usize {
        self.states.len()
    }
}

pub type StateLookups = HashMap<(Vec<String>, usize, usize), Option<VarState>>;

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
                kind: CompErrorKind::Unknown(format!(
                    "Error: Enable signal {:?} never asserted.",
                    enable.join(".")
                )),
            })?;
        debug!("ModuleControls offset: {}", offset);
        Ok(Self::new(vcd_states, root_module, offset))
    }
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
    pub fn lookups(self) -> StateLookups {
        self.accessed
    }
    pub fn len(&self) -> usize {
        self.vcd_states.len() - self.offset
    }
}

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

#[cfg_attr(feature = "flame_it", flame)]
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
                                return Err(CompError::no_mod(CompErrorKind::Unknown(format!(
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
