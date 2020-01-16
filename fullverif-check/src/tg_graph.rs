//! Dataflow graph generation and security properties verification.

use crate::clk_vcd;
use crate::error::{CResult, CompError, CompErrorKind, CompErrors};
use crate::gadget_internals::{self, Connection, GName, RndConnection};
use crate::gadgets::{self, Input, Latency, Sharing};
use crate::netlist::{self, RndLatencies};
use petgraph::{
    graph::{self, NodeIndex},
    visit::{EdgeRef, IntoNodeIdentifiers, IntoNodeReferences},
    Direction, Graph,
};
use std::collections::{BinaryHeap, HashMap, HashSet};

/// A gadget id in the GadgetFlow
pub type Name<'a> = (GName<'a>, Latency);

/// A randomness input bit in the GadgetFlow
pub type TRandom<'a> = (gadgets::Random<'a>, Latency);

/// A connection to a randomness gate in the GadgetFlow
pub type TRndConnection<'a> = (RndConnection<'a>, Latency);

/// Trace source of randomness (built for user display purposes)
type RndTrace<'a> = Vec<(RndConnection<'a>, gadgets::Latency)>;

/// A gadget in the GadgetFlow
#[derive(Clone)]
struct GadgetNode<'a, 'b> {
    base: gadget_internals::GadgetInstance<'a, 'b>,
    name: Name<'a>,
    random_connections: HashMap<TRandom<'a>, TRndConnection<'a>>,
}

impl<'a, 'b> std::fmt::Debug for GadgetNode<'a, 'b> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "GadgetNode({:?})", self.name)
    }
}

/// A node in the GadgetFlow: gadget, input, output or invalid
#[derive(Debug, Clone)]
enum GFNode<'a, 'b> {
    Gadget(GadgetNode<'a, 'b>),
    Input(Latency),
    Output,
    Invalid,
}

impl<'a, 'b> GFNode<'a, 'b> {
    fn is_gadget(&self) -> bool {
        if let GFNode::Gadget(_) = self {
            true
        } else {
            false
        }
    }
}

/// Dependency of the content of a wire on the secrets.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sensitive {
    /// Not sensitive.
    No,
    /// Dependency only in the glitch domain, but stable value is not sensitive.
    Glitch,
    /// Sensitive.
    Yes,
}

/// An edge in the basic FlowGraph
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Edge<'a> {
    output: Sharing<'a>,
    input: Input<'a>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// An edge in the annotated FlowGraph
pub struct AEdge<'a> {
    edge: Edge<'a>,
    valid: bool,
    sensitive: Sensitive,
}

/// Data flow graph for gadget.
/// Built by repeating the GadgetInternals in the time dimension,
/// and connecting gadgets according to latency annotations.
pub struct GadgetFlow<'a, 'b, E> {
    pub internals: gadget_internals::GadgetInternals<'a, 'b>,
    gadgets: Graph<GFNode<'a, 'b>, E>,
    n_cycles: Latency,
    o_node: petgraph::graph::NodeIndex,
    inv_node_in: petgraph::graph::NodeIndex,
    inv_node_out: petgraph::graph::NodeIndex,
    i_nodes: Vec<petgraph::graph::NodeIndex>,
}

/// Non-annocated GadgetFlow.
pub type BGadgetFlow<'a, 'b> = GadgetFlow<'a, 'b, Edge<'a>>;

/// Annotated GadgetFlow: validity and sensitivity information is included in each edge.
pub type AGadgetFlow<'a, 'b> = GadgetFlow<'a, 'b, AEdge<'a>>;

const EMPTY_SHARING: Sharing = Sharing {
    port_name: "",
    pos: 0,
};

impl<'a, 'b, E> GadgetFlow<'a, 'b, E> {
    /// Returns the value of the control signal of each mux gadget in the graph.
    /// Returns None when the signal is invalid (either x or y).
    fn muxes_controls(
        &self,
        controls: &mut clk_vcd::ModuleControls,
    ) -> CResult<'a, HashMap<NodeIndex, Option<bool>>> {
        let mut muxes_ctrls = HashMap::<NodeIndex, Option<bool>>::new();
        for (idx, tginst) in self.gadgets.node_references() {
            if let GFNode::Gadget(gadget) = tginst {
                if gadget.base.kind.prop == netlist::GadgetProp::Mux {
                    let sel_name = "sel".to_owned();
                    let path: Vec<String> =
                        vec![(*(gadget.name.0).get()).to_owned(), sel_name.to_owned()];
                    let sel = controls
                        .lookup(path, gadget.name.1 as usize, 0)?
                        .unwrap_or_else(|| {
                            panic!(
                                "Missing simulation cycle for mux selector, gadget: {:?}",
                                gadget.name
                            )
                        });
                    let sel = match sel {
                        clk_vcd::VarState::Scalar(vcd::Value::V0) => Some(false),
                        clk_vcd::VarState::Scalar(vcd::Value::V1) => Some(true),
                        clk_vcd::VarState::Vector(_) => unreachable!(),
                        clk_vcd::VarState::Uninit => unreachable!(),
                        clk_vcd::VarState::Scalar(vcd::Value::X)
                        | clk_vcd::VarState::Scalar(vcd::Value::Z) => None,
                    };
                    muxes_ctrls.insert(idx, sel);
                }
            }
        }
        Ok(muxes_ctrls)
    }

    /// Iterator on the input edges of gadget.
    fn g_inputs(&self, gadget: NodeIndex) -> graph::Edges<E, petgraph::Directed> {
        self.gadgets.edges_directed(gadget, Direction::Incoming)
    }

    /// Iterator on the output edges of gadget.
    fn g_outputs(&self, gadget: NodeIndex) -> graph::Edges<E, petgraph::Directed> {
        self.gadgets.edges_directed(gadget, Direction::Outgoing)
    }

    /// Iterator of all the gadgets in the graph.
    fn gadgets<'s>(&'s self) -> impl Iterator<Item = (NodeIndex, &'s GadgetNode<'a, 'b>)> + 's {
        self.gadgets.node_identifiers().filter_map(move |idx| {
            if let &GFNode::Gadget(ref gadget) = &self.gadgets[idx] {
                Some((idx, gadget))
            } else {
                None
            }
        })
    }

    /// Iterator of the ids of the gadgets in the graph.
    pub fn gadget_names<'s>(&'s self) -> impl Iterator<Item = Name<'a>> + 's {
        self.gadgets().map(|(_, g)| g.name)
    }

    /// Get the gadget with the given node index. (Panics on error.)
    fn gadget(&self, idx: NodeIndex) -> &GadgetNode<'a, 'b> {
        if let GFNode::Gadget(ref gadget) = &self.gadgets[idx] {
            gadget
        } else {
            panic!("Gadget at index {:?} is not a gadget.", idx)
        }
    }
}

impl<'a, 'b, E: std::fmt::Debug> GadgetFlow<'a, 'b, E> {
    /// Show an edge
    fn disp_edge(&self, e: petgraph::graph::EdgeReference<E>) -> String {
        format!(
            "from {:?} to {:?}, {:?}",
            self.gadgets[e.source()],
            self.gadgets[e.target()],
            e.weight()
        )
    }
}

impl<'a, 'b> BGadgetFlow<'a, 'b> {
    /// Build (non-annotated) a GadgetFlow graph from the GadgetInternals, for n_cycles execution
    /// cycles.
    pub fn unroll(
        internals: gadget_internals::GadgetInternals<'a, 'b>,
        n_cycles: Latency,
    ) -> CResult<'a, Self> {
        let mut gadgets = Graph::new();
        let o_node = gadgets.add_node(GFNode::Output);
        let inv_node_in = gadgets.add_node(GFNode::Invalid);
        let inv_node_out = gadgets.add_node(GFNode::Invalid);
        let i_nodes = (0..n_cycles)
            .map(|lat| gadgets.add_node(GFNode::Input(lat)))
            .collect::<Vec<_>>();
        let mut g_nodes = HashMap::new();
        for (name, sgi) in internals.subgadgets.iter() {
            for lat in 0..n_cycles {
                let g = gadgets.add_node(GFNode::Gadget(GadgetNode {
                    base: sgi.clone(),
                    name: (*name, lat),
                    random_connections: random_connections(sgi, lat)?,
                }));
                g_nodes.insert((*name, lat), g);
            }
        }
        for (name, sgi) in internals.subgadgets.iter() {
            for cycle in 0..n_cycles {
                for input in sgi.kind.inputs() {
                    let (src_g, src_o) = time_connection(
                        &sgi.input_connections[&input.0],
                        &internals,
                        input.1,
                        cycle,
                        n_cycles,
                        &i_nodes,
                        &g_nodes,
                        inv_node_in,
                    );
                    gadgets.add_edge(
                        src_g,
                        g_nodes[&(*name, cycle)],
                        Edge {
                            output: src_o,
                            input,
                        },
                    );
                }
            }
        }
        for (output, conn) in internals.output_connections.iter() {
            for cycle in 0..n_cycles {
                let (src_g, src_o) = time_connection(
                    conn,
                    &internals,
                    0,
                    cycle,
                    n_cycles,
                    &i_nodes,
                    &g_nodes,
                    inv_node_in,
                );
                gadgets.add_edge(
                    src_g,
                    o_node,
                    Edge {
                        output: src_o,
                        input: (*output, cycle),
                    },
                );
            }
        }
        let mut res = Self {
            internals,
            gadgets,
            n_cycles,
            o_node,
            inv_node_in,
            inv_node_out,
            i_nodes,
        };
        for (name, sgi) in res.internals.subgadgets.iter() {
            for cycle in 0..n_cycles {
                let node = g_nodes[&(*name, cycle)];
                let present_outputs = res
                    .g_outputs(node)
                    .map(|e| e.weight().output)
                    .collect::<HashSet<_>>();
                for output in sgi.kind.outputs.keys() {
                    if !present_outputs.contains(&output) {
                        // output missing: it is not used in any gadget in the valid time range
                        res.gadgets.add_edge(
                            node,
                            inv_node_out,
                            Edge {
                                output: *output,
                                input: (EMPTY_SHARING, 0),
                            },
                        );
                    }
                }
            }
        }
        return Ok(res);
    }

    /// Sort the nodes in the graph, inputs first.
    /// Does not take into account the non-selected edge of a mux for the ordering.
    /// Err if there is a cycle in the graph.
    fn toposort(
        &self,
        muxes_ctrls: &HashMap<NodeIndex, Option<bool>>,
    ) -> CResult<'a, Vec<NodeIndex>> {
        let mut edges_kept = vec![true; self.gadgets.raw_edges().len()];
        for (idx, ctrl) in muxes_ctrls.iter() {
            if let Some(ctrl) = ctrl {
                // invert because we remove the input
                let input = if !*ctrl { "in_true" } else { "in_false" };
                for e in self.g_inputs(*idx) {
                    if (e.weight().input).0.port_name == input {
                        edges_kept[e.id().index()] = false;
                    }
                }
            }
        }
        let mut gadgets = self.gadgets.clone();
        //gadgets.retain_edges(|_, e| edges_kept[e.index()]);
        gadgets.clear_edges();
        for (k, e) in edges_kept.into_iter().zip(self.gadgets.raw_edges().iter()) {
            if k {
                gadgets.add_edge(e.source(), e.target(), e.weight.clone());
            }
        }
        Ok(petgraph::algo::toposort(&gadgets, None).map_err(|cycle| {
            CompError::ref_nw(
                &self.internals.gadget.module,
                CompErrorKind::Other(format!(
                    "Looping data depdendency containing gadget {:?}",
                    gadgets[cycle.node_id()]
                )),
            )
        })?)
    }

    /// Compute validity and sensitivity information for each edge.
    fn annotate_inner(
        &self,
        muxes_ctrls: &HashMap<NodeIndex, Option<bool>>,
        sorted_nodes: &[NodeIndex],
    ) -> Result<(Vec<bool>, Vec<Sensitive>), CompError<'a>> {
        let mut edges_valid: Vec<Option<bool>> = vec![None; self.gadgets.edge_count()];
        let mut edges_sensitive: Vec<Option<Sensitive>> = vec![None; self.gadgets.edge_count()];
        for idx in sorted_nodes.into_iter() {
            match &self.gadgets[*idx] {
                GFNode::Gadget(_) => {
                    let max_output = self.g_outputs(*idx).map(|e| e.weight().output.pos).max();
                    if let (Some(ctrl), Some(max_output)) = (muxes_ctrls.get(idx), max_output) {
                        //let mut outputs: Vec<bool> = vec![false; max_output as usize + 1];
                        let mut outputs_valid: Vec<Option<bool>> =
                            vec![None; max_output as usize + 1];
                        let mut outputs_sensitive: Vec<Option<Sensitive>> =
                            vec![None; max_output as usize + 1];
                        if let Some(ctrl) = ctrl {
                            let input = if *ctrl { "in_true" } else { "in_false" };
                            for e_i in self.g_inputs(*idx) {
                                let Sharing { port_name, pos } = &e_i.weight().input.0;
                                if port_name == &input {
                                    outputs_valid[*pos as usize] = edges_valid[e_i.id().index()];
                                    // Neglect glitches for now, will come to it later
                                    outputs_sensitive[*pos as usize] =
                                        edges_sensitive[e_i.id().index()];
                                }
                            }
                        } else {
                            for e_i in self.g_inputs(*idx) {
                                let Sharing { pos, .. } = &e_i.weight().input.0;
                                if *pos > max_output {
                                    panic!(
                                        "pos: {}, max_output (): {}, name: {:?}, base: {:?}\noutputs:{:?}",
                                        *pos,
                                        max_output,
                                        self.gadgets[*idx],
                                        self.gadget(*idx).base.kind,
                                        self.g_outputs(*idx).collect::<Vec<_>>()
                                    );
                                }
                                outputs_valid[*pos as usize] = Some(false);
                                let sens_new = edges_sensitive[e_i.id().index()].unwrap();
                                let sens =
                                    outputs_sensitive[*pos as usize].get_or_insert(Sensitive::No);
                                *sens = (*sens).max(sens_new);
                            }
                        }
                        for o_e in self.g_outputs(*idx) {
                            let pos = o_e.weight().output.pos as usize;
                            edges_valid[o_e.id().index()] = outputs_valid[pos];
                            edges_sensitive[o_e.id().index()] = outputs_sensitive[pos];
                        }
                    } else {
                        let g_valid = self.g_inputs(*idx).all(|e| {
                            edges_valid[e.id().index()].unwrap_or_else(|| {
                                panic!(
                                "Non-initialized validity for edge {}, src node pos: {:?}, target node pos: {:?}",
                                self.disp_edge(e),
                                sorted_nodes.iter().find(|x| **x== e.source()),
                                sorted_nodes.iter().find(|x| **x == e.target()),
                            );})
                        });
                        let g_sensitive = self
                            .g_inputs(*idx)
                            .map(|e| {
                                edges_sensitive[e.id().index()]
                                    .expect("Non-initialized sensitivity")
                            })
                            .max()
                            .unwrap_or(Sensitive::No);
                        for e in self.g_outputs(*idx) {
                            edges_valid[e.id().index()] = Some(g_valid);
                            edges_sensitive[e.id().index()] = Some(g_sensitive);
                        }
                    }
                }
                GFNode::Input(lat) => {
                    for e in self.g_outputs(*idx) {
                        let Edge { output, .. } = e.weight();
                        let valid = self.internals.gadget.inputs[output].contains(&lat);
                        edges_valid[e.id().index()] = Some(valid);
                        // Worst-case analysis: we assume there may be glitches on the inputs.
                        edges_sensitive[e.id().index()] = if valid {
                            Some(Sensitive::Yes)
                        } else {
                            Some(Sensitive::Glitch)
                        };
                    }
                }
                GFNode::Output => {
                    assert!(self.g_outputs(*idx).next().is_none());
                }
                GFNode::Invalid => {
                    // Connections from non-existing gadgets or out of range inputs.
                    // Assume that they are non-sensitive (might want to assume glitch ?)
                    for e in self.g_outputs(*idx) {
                        edges_valid[e.id().index()] = Some(false);
                        edges_sensitive[e.id().index()] = Some(Sensitive::No);
                    }
                }
            }
            for e in self.g_outputs(*idx) {
                assert!(
                    edges_valid[e.id().index()].is_some(),
                    "Failed init valid for edge {}",
                    self.disp_edge(e)
                );
                assert!(
                    edges_sensitive[e.id().index()].is_some(),
                    "Failed init sensitive for edge {}",
                    self.disp_edge(e)
                );
            }
        }
        // move sensitivity to full form
        let mut edges_sensitive = edges_sensitive
            .into_iter()
            .map(|x| x.unwrap().into())
            .collect::<Vec<Sensitive>>();
        // Propagate glitches
        // Stack of gadgets on which to propagate glitches
        let mut gl_to_analyze = self.gadgets().map(|x| x.0).collect::<BinaryHeap<_>>();
        while let Some(idx) = gl_to_analyze.pop() {
            let noglitch_cycle = compute_sensitivity(
                self.g_inputs(idx)
                    .map(|e| (edges_sensitive[e.id().index()], e.weight().input)),
            );
            if noglitch_cycle == 0 {
                continue;
            }
            for e in self.g_outputs(idx) {
                if edges_sensitive[e.id().index()] == Sensitive::No {
                    let output_lat = *self
                        .gadget(idx)
                        .base
                        .kind
                        .outputs
                        .get(&e.weight().output)
                        .unwrap();
                    if output_lat < noglitch_cycle {
                        edges_sensitive[e.id().index()] = Sensitive::Glitch;
                        if self.gadgets[e.target()].is_gadget() {
                            gl_to_analyze.push(e.target());
                        }
                    }
                }
            }
        }
        Ok((
            edges_valid.into_iter().map(Option::unwrap).collect(),
            edges_sensitive,
        ))
    }

    /// Compute validity and sensitivity information. Build an annotated GadgetFlow.
    pub fn annotate(
        &self,
        controls: &mut clk_vcd::ModuleControls,
    ) -> CResult<'a, AGadgetFlow<'a, 'b>> {
        let muxes_ctrls = self.muxes_controls(controls)?;
        let sorted_nodes = self.toposort(&muxes_ctrls)?;
        let (validities, sensitivities) = self.annotate_inner(&muxes_ctrls, &sorted_nodes)?;
        let mut new_gadgets = Graph::with_capacity(
            self.gadgets.raw_nodes().len(),
            self.gadgets.raw_edges().len(),
        );
        for (i, n) in self.gadgets.raw_nodes().iter().enumerate() {
            assert_eq!(i, new_gadgets.add_node(n.weight.clone()).index());
        }
        for (i, e) in self.gadgets.raw_edges().iter().enumerate() {
            assert_eq!(
                i,
                new_gadgets
                    .add_edge(
                        e.source(),
                        e.target(),
                        AEdge {
                            edge: e.weight.clone(),
                            valid: validities[i],
                            sensitive: sensitivities[i],
                        }
                    )
                    .index()
            );
        }
        Ok(AGadgetFlow {
            gadgets: new_gadgets,
            internals: self.internals.clone(),
            n_cycles: self.n_cycles,
            o_node: self.o_node,
            inv_node_in: self.inv_node_in,
            inv_node_out: self.inv_node_out,
            i_nodes: self.i_nodes.clone(),
        })
    }
}

impl<'a, 'b> AGadgetFlow<'a, 'b> {
    /// Is the gadget n valid, that is, are all the inputs of node n valid ?
    fn gadget_valid(&self, n: NodeIndex) -> bool {
        self.g_inputs(n).all(|e| e.weight().valid)
    }

    /// Is the gadget n sensitive, that is, is any of the inputs of node n sensitive (in the
    /// non-glitch domain) ?
    fn gadget_sensitive(&self, n: NodeIndex) -> bool {
        self.g_inputs(n)
            .any(|e| e.weight().sensitive == Sensitive::Yes)
    }

    /// List the latencies at which each gadget is valid.
    pub fn list_valid(&self) -> HashMap<GName<'a>, Vec<Latency>> {
        let mut gadgets = HashMap::new();
        for (id, gadget) in self.gadgets() {
            if gadget.base.kind.prop != netlist::GadgetProp::Mux && self.gadget_valid(id) {
                gadgets
                    .entry(gadget.name.0)
                    .or_insert_with(Vec::new)
                    .push(gadget.name.1);
            }
        }
        for cycles in gadgets.values_mut() {
            cycles.sort_unstable();
        }
        gadgets
    }

    /// List the latencies at which each gadget is sensitive.
    pub fn list_sensitive(&self) -> HashMap<GName<'a>, Vec<Latency>> {
        let mut gadgets = HashMap::new();
        for (id, gadget) in self.gadgets() {
            if gadget.base.kind.prop != netlist::GadgetProp::Mux && self.gadget_sensitive(id) {
                gadgets
                    .entry(gadget.name.0)
                    .or_insert_with(Vec::new)
                    .push(gadget.name.1);
            }
        }
        for cycles in gadgets.values_mut() {
            cycles.sort_unstable();
        }
        gadgets
    }

    /// Returns the list of gadgets that are sensitive, not valid, and have randomness inputs.
    pub fn warn_useless_rnd(&self) -> Vec<Name<'a>> {
        self.gadgets()
            .filter(|(idx, gadget)| {
                !gadget.random_connections.is_empty()
                    && self.gadget_sensitive(*idx)
                    && !self.gadget_valid(*idx)
            })
            .map(|(_, g)| g.name)
            .collect()
    }

    /// Display a full representation of the annotated GadgetFlow
    pub fn disp_full(&self) {
        for (id, gadget) in self.gadgets() {
            println!("Gadget {:?}:", gadget.name);
            println!("Inputs:");
            for e in self.g_inputs(id) {
                let AEdge {
                    edge: Edge { input, .. },
                    valid,
                    sensitive,
                } = e.weight();
                println!(
                    "\tinput ({}[{}], {}): Valid: {:?}, Sensitive: {:?}",
                    input.0.port_name, input.0.pos, input.1, valid, sensitive
                );
            }
            for e in self.g_outputs(id) {
                let AEdge {
                    edge: Edge { output, .. },
                    valid,
                    sensitive,
                } = e.weight();
                println!(
                    "\toutput {}[{}]: Valid: {:?}, Sensitive: {:?}",
                    output.port_name, output.pos, valid, sensitive
                );
            }
        }
    }

    /// Checks that all the inputs are valid when the should be valid according to specification.
    pub fn check_valid_outputs(&self) -> CResult<'a, ()> {
        let valid_outputs = self
            .g_inputs(self.o_node)
            .filter_map(|e| {
                if e.weight().valid {
                    Some(e.weight().edge.input)
                } else {
                    None
                }
            })
            .collect::<HashSet<_>>();
        let missing_outputs = self
            .internals
            .gadget
            .outputs
            .iter()
            .map(|(sh, lat)| (*sh, *lat))
            .filter(|(sh, lat)| !valid_outputs.contains(&(*sh, *lat)))
            .collect::<Vec<_>>();
        if !missing_outputs.is_empty() {
            Err(CompError::ref_nw(
                &self.internals.gadget.module,
                CompErrorKind::OutputNotValid(missing_outputs),
            ))?;
        }
        let excedentary_outputs = self
            .g_inputs(self.o_node)
            .filter_map(|e| {
                // We don't care about glitches, those are inferred and always assumed by the
                // outside world.
                if e.weight().sensitive == Sensitive::Yes {
                    let (sh, lat) = e.weight().edge.input;
                    if self.internals.gadget.outputs.get(&sh).map(|l| *l == lat) != Some(true) {
                        return Some((sh, lat));
                    }
                }
                return None;
            })
            .collect::<Vec<_>>();
        if !excedentary_outputs.is_empty() {
            Err(CompError::ref_nw(
                &self.internals.gadget.module,
                CompErrorKind::ExcedentaryOutput(excedentary_outputs),
            ))?;
        }
        Ok(())
    }

    /// Returns the cycles at which each randomness input is used.
    pub fn randoms_input_timing(
        &self,
        controls: &mut clk_vcd::ModuleControls,
    ) -> CResult<'a, HashMap<TRandom<'a>, (Name<'a>, TRandom<'a>)>> {
        let mut rnd_gadget2input: Vec<HashMap<TRandom<'a>, Option<TRandom<'a>>>> =
            vec![HashMap::new(); self.gadgets.node_count()];
        let mut name_cache = HashMap::new();
        let mut errors: Vec<CompError<'a>> = Vec::new();
        println!("starting randoms_input_timing");
        let mut i = 0;
        for (idx, gadget) in self.gadgets() {
            for conn in gadget.random_connections.keys() {
                i += 1;
                let rnd_in =
                    random_to_input(&self.internals, controls, gadget, conn, &mut name_cache);
                if let Err(e) = &rnd_in {
                    if self.gadget_sensitive(idx) {
                        errors.extend_from_slice(&e.0);
                    }
                }
                rnd_gadget2input[idx.index()].insert(*conn, rnd_in.ok().map(|x| x.0));
            }
        }
        if !errors.is_empty() {
            return Err(CompErrors::new(errors));
        }
        println!("rnd_gadget2input done, i: {}", i);
        let mut rnd_input2use: HashMap<TRandom<'a>, Vec<(NodeIndex, TRandom<'a>)>> = HashMap::new();
        for (idx, rnd2input) in rnd_gadget2input.iter().enumerate() {
            for (rnd, rnd_input) in rnd2input.iter() {
                if let Some(input) = rnd_input {
                    rnd_input2use
                        .entry(*input)
                        .or_default()
                        .push((NodeIndex::new(idx), *rnd));
                }
            }
        }
        println!("rnd_input2use done");
        let mut res: HashMap<TRandom<'a>, (Name<'a>, TRandom<'a>)> = HashMap::new();
        for (in_rnd, uses) in rnd_input2use.iter() {
            assert!(!uses.is_empty());
            if uses.iter().any(|(idx, _)| self.gadget_sensitive(*idx)) {
                if uses.len() > 1 {
                    let random_uses = uses
                        .iter()
                        .map(|(idx, rnd)| {
                            let gadget = self.gadget(*idx);
                            (
                                (gadget.name, rnd.clone()),
                                random_to_input(
                                    &self.internals,
                                    controls,
                                    gadget,
                                    rnd,
                                    &mut name_cache,
                                )
                                .unwrap()
                                .1,
                            )
                        })
                        .collect::<Vec<_>>();
                    errors.push(CompError::ref_nw(
                        &self.internals.gadget.module,
                        CompErrorKind::MultipleUseRandom {
                            random: *in_rnd,
                            uses: random_uses,
                        },
                    ));
                    if errors.len() >= 100 {
                        break;
                    }
                } else {
                    let GadgetNode { name, .. } = self.gadget(uses[0].0);
                    res.insert(*in_rnd, (*name, uses[0].1));
                }
            }
        }
        println!("res done");
        if !errors.is_empty() {
            return Err(CompErrors::new(errors));
        }
        Ok(res)
    }

    pub fn check_randomness_usage(
        &self,
        controls: &mut clk_vcd::ModuleControls,
    ) -> CResult<'a, ()> {
        for (rnd, lats) in self.internals.gadget.randoms.iter() {
            if lats.is_none() {
                return Err(CompError::missing_annotation(
                    &self.internals.gadget.module,
                    rnd.port_name,
                    "fv_latency",
                )
                .into());
            }
        }
        let errors = self
            .randoms_input_timing(controls)?
            .keys()
            .map(|(rnd, lat)|
                match &self.internals.gadget.randoms[rnd] {
                    Some(RndLatencies::Attr(lats)) => if lats.contains(lat) {
                        Ok(()) } else {
                        Err(CompError::other(
                                &self.internals.gadget.module,
                                rnd.port_name,
                                &format!("Random input {} is used at cycle {} while not valid at that cycle.", rnd, lat)
                        ))
                    }
                    Some(RndLatencies::Wire { wire_name, offset }) => {
                        let cycle = <u32 as std::convert::TryFrom<i32>>::try_from(
                            (*lat as i32) + offset).map_err(|_| CompError::other(
                                &self.internals.gadget.module,
                                rnd.port_name,
                                &format!("For random at cycle {}, control signal cycle is negative (offset: {})", lat, offset)
                            )
                            )?;
                        let valid = controls.lookup(
                            vec![wire_name.clone()],
                            cycle as usize, 0
                            )?.and_then(|var_state|
                            var_state.to_bool()).ok_or_else(|| CompError::other(
                                &self.internals.gadget.module,
                                rnd.port_name,
                                &format!("Valid-indicating wire has no value at cycle {} (for rnd at cycle {})", cycle, lat)
                                )
                            )?;
                        if valid {
                            Ok(())
                        } else {
                                Err(CompError::other(
                                        &self.internals.gadget.module,
                                        rnd.port_name,
                                        &format!("Random input {} is used at cycle {} while not valid at that cycle.", rnd, lat)
                                ))
                        }
                    }
                    None =>
                Err(CompError::ref_sn(
                    &self.internals.gadget.module,
                    rnd.port_name,
                    CompErrorKind::Other("Sub-gadget randomness inputs must be annotated with the 'fv_latency' attribute".to_string()),
                ))
                })
        .filter_map(Result::err)
            .collect::<Vec<_>>();
        CompErrors::result(errors)
    }

    /// Verifies that there is no any more sensitive state in the circuit after n_cycles.
    pub fn check_state_cleared(&self) -> CResult<'a, ()> {
        let errors = self
            .gadgets()
            .filter(|(idx, _)| self.gadget_sensitive(*idx))
            .flat_map(|(idx, gadget)| {
                self.g_outputs(idx).filter_map(move |e| {
                    let out_lat = gadget.base.kind.outputs[&e.weight().edge.output];
                    if gadget.name.1 + out_lat > self.n_cycles - 1 {
                        Some(CompError::ref_nw(
                            &self.internals.gadget.module,
                            CompErrorKind::LateOutput(
                                gadget.name.1 + out_lat - self.n_cycles + 1,
                                (*gadget.name.0.get()).to_owned(),
                                e.weight().edge.output,
                            ),
                        ))
                    } else {
                        None
                    }
                })
            })
            .collect::<Vec<_>>();
        CompErrors::result(errors)
    }

    /// Iterator over sensitive gadgets.
    pub fn sensitive_gadgets<'s>(
        &'s self,
    ) -> impl Iterator<Item = (Name<'a>, &'s gadget_internals::GadgetInstance<'a, 'b>)> + 's {
        self.gadgets()
            .filter(move |(idx, _)| self.gadget_sensitive(*idx))
            .map(|(_, g)| (g.name, &g.base))
    }
}

fn compute_sensitivity<'a>(inputs: impl Iterator<Item = (Sensitive, Input<'a>)>) -> Latency {
    inputs
        .filter(|(sensitive, _)| *sensitive != Sensitive::No)
        .map(|(_, (_, lat))| lat)
        .max()
        .map(|x| x + 1)
        .unwrap_or(0)
}

// Returns None if input is late
fn random_to_input<'a, 'b>(
    internals: &gadget_internals::GadgetInternals<'a, 'b>,
    controls: &mut clk_vcd::ModuleControls,
    gadget: &GadgetNode<'a, 'b>,
    rnd_name: &TRandom<'a>,
    names_cache: &mut HashMap<&'a str, (&'a str, usize)>,
) -> CResult<'a, (TRandom<'a>, RndTrace<'a>)> {
    let module = internals.gadget.module;
    let trandom = &gadget.random_connections[rnd_name];
    let mut trandom_w: Vec<(RndConnection<'a>, gadgets::Latency)> = vec![(trandom.0, trandom.1)];
    loop {
        let rnd_to_add = match &trandom_w[trandom_w.len() - 1] {
            (RndConnection::Invalid(bit), _) => {
                return Err(CompError::ref_nw(
                    module,
                    CompErrorKind::InvalidRandom(trandom_w.clone(), gadget.name, *rnd_name, *bit),
                )
                .into());
            }
            (RndConnection::Port(rnd), cycle) => {
                return Ok((((*rnd, *cycle)), trandom_w.clone()));
            }
            (RndConnection::Gate(gate_id), cycle) => match &internals.rnd_gates[&gate_id] {
                gadget_internals::RndGate::Reg { input: new_conn } => {
                    if *cycle == 0 {
                        Err(CompError::ref_nw(module, CompErrorKind::Other(format!("Randomness for random {:?} of gadget {:?} comes from a cycle before cycle 0 (through reg {:?})", rnd_name, gadget.name, gate_id))))?;
                    }
                    (*new_conn, cycle - 1)
                }
                gadget_internals::RndGate::Mux { ina, inb } => {
                    let (var_name, offset) = names_cache.entry(gate_id.cell).or_insert_with(|| {
                        netlist::get_names(module, module.cells[gate_id.cell].connections["S"][0])
                            .next()
                            .expect("No names for net")
                    });
                    let var_name = netlist::format_name(var_name);
                    match controls.lookup(vec![var_name], *cycle as usize, *offset)? {
                        None => {
                            return Err(CompError::ref_nw(
                                module,
                                CompErrorKind::Other(format!(
                                    "Random comes from a late gate for gadget {:?}",
                                    gadget.name
                                )),
                            )
                            .into());
                        }
                        Some(clk_vcd::VarState::Scalar(vcd::Value::V0)) => (*ina, *cycle),
                        Some(clk_vcd::VarState::Scalar(vcd::Value::V1)) => (*inb, *cycle),
                        Some(clk_vcd::VarState::Vector(_)) => unreachable!(),
                        Some(sel @ clk_vcd::VarState::Scalar(vcd::Value::Z))
                        | Some(sel @ clk_vcd::VarState::Uninit)
                        | Some(sel @ clk_vcd::VarState::Scalar(vcd::Value::X)) => {
                            return Err(CompError::ref_nw(module, CompErrorKind::Other(format!(
                                    "Invalid control signal {:?} for mux {} at cycle {} for randomness", sel,
                                    gate_id.cell, cycle
                                ))).into());
                        }
                    }
                }
            },
        };
        trandom_w.push(rnd_to_add);
    }
}

/// Build a map random input -> timed random connections for a gadget.
fn random_connections<'a, 'b>(
    sgi: &gadget_internals::GadgetInstance<'a, 'b>,
    cycle: u32,
) -> CResult<'a, HashMap<TRandom<'a>, TRndConnection<'a>>> {
    let mut res = HashMap::new();
    for (r_name, random_lats) in sgi.kind.randoms.iter() {
        match random_lats {
            Some(netlist::RndLatencies::Attr(random_lats)) => {
                for lat in random_lats.iter() {
                    res.insert(
                        (*r_name, *lat),
                        (sgi.random_connections[r_name], lat + cycle),
                    );
                }
            }
            Some(netlist::RndLatencies::Wire { .. }) | None => {
                Err(CompError::ref_sn(
                    sgi.kind.module,
                    &r_name.port_name,
                    CompErrorKind::MissingAnnotation("fv_lat".to_owned()),
                ))?;
            }
        }
    }
    Ok(res)
}

/// Find the source GadgetFlow node for a Connection at the given cycle.
fn time_connection<'a, 'b>(
    conn: &gadget_internals::Connection<'a>,
    internals: &gadget_internals::GadgetInternals<'a, 'b>,
    src_latency: Latency,
    cycle: Latency,
    n_cycles: Latency,
    i_nodes: &Vec<NodeIndex>,
    g_nodes: &HashMap<Name<'a>, NodeIndex>,
    inv_node: NodeIndex,
) -> (NodeIndex, Sharing<'a>) {
    match conn {
        Connection::GadgetOutput {
            gadget_name,
            output,
        } => {
            let output_latency = internals.subgadgets[gadget_name].kind.outputs[output];
            if let Some(ref_cycle) = (cycle + src_latency)
                .checked_sub(output_latency)
                .filter(|ref_cycle| *ref_cycle < n_cycles)
            {
                return (g_nodes[&(*gadget_name, ref_cycle)], *output);
            }
        }
        Connection::Input(input) => {
            let in_lat = src_latency + cycle;
            if internals.gadget.inputs[input].contains(&in_lat) {
                return (i_nodes[in_lat as usize], *input);
            }
        }
    }
    (inv_node, EMPTY_SHARING)
}
