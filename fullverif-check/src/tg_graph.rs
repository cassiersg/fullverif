//! Dataflow graph generation and security properties verification.

use crate::clk_vcd;
use crate::error::{CResult, CompError, CompErrorKind, CompErrors};
use crate::gadget_internals::{self, Connection, GName, RndConnection};
use crate::gadgets::{self, Input, Latency, Sharing};
use crate::netlist::{self, RndLatencies};
use petgraph::{
    graph::{self, EdgeReference, NodeIndex},
    visit::{EdgeFiltered, EdgeRef, IntoNodeIdentifiers},
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
        self.gadget().is_some()
    }
    fn gadget(&self) -> Option<&GadgetNode<'a, 'b>> {
        if let GFNode::Gadget(gn) = self {
            Some(gn)
        } else {
            None
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

/// A GadgetGraph
#[derive(derive_more::Deref, derive_more::DerefMut)]
struct GGraph<'a, 'b>(Graph<GFNode<'a, 'b>, Edge<'a>>);

/// Data flow graph for gadget.
/// Built by repeating the GadgetInternals in the time dimension,
/// and connecting gadgets according to latency annotations.
pub struct GadgetFlow<'a, 'b> {
    pub internals: gadget_internals::GadgetInternals<'a, 'b>,
    ggraph: GGraph<'a, 'b>,
    g_nodes: HashMap<Name<'a>, NodeIndex>,
    n_cycles: Latency,
    o_node: petgraph::graph::NodeIndex,
    muxes_ctrls: HashMap<NodeIndex, Option<bool>>,
    edge_validity: Vec<bool>,
    edge_sensitivity: Vec<Sensitive>,
}

const EMPTY_SHARING: Sharing = Sharing {
    port_name: "",
    pos: 0,
};

/// Returns the value of the control signal of each mux gadget in the graph.
/// Returns None when the signal is invalid (either x or y).
fn mux_ctrls<'a, 'b, 's, Idx: std::hash::Hash + std::cmp::Eq>(
    gadgets: impl Iterator<Item = (Idx, &'s GadgetNode<'a, 'b>)>,
    controls: &'s mut clk_vcd::ModuleControls,
) -> CResult<'a, HashMap<Idx, Option<bool>>>
where
    'a: 'b,
    'b: 's,
{
    let mut res = HashMap::new();
    for (idx, gadget) in gadgets {
        if gadget.base.kind.prop == netlist::GadgetProp::Mux {
            let sel_name = "sel".to_owned();
            let path: Vec<String> = vec![(*(gadget.name.0).get()).to_owned(), sel_name.to_owned()];
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
            res.insert(idx, sel);
        }
    }
    return Ok(res);
}

impl<'a, 'b> GGraph<'a, 'b> {
    /// Iterator of all the gadgets in the graph.
    fn gadgets<'s>(&'s self) -> impl Iterator<Item = (NodeIndex, &'s GadgetNode<'a, 'b>)> + 's {
        self.node_identifiers().filter_map(move |idx| {
            if let &GFNode::Gadget(ref gadget) = &self[idx] {
                Some((idx, gadget))
            } else {
                None
            }
        })
    }
    /// Iterator on the input edges of gadget.
    fn g_inputs(&self, gadget: NodeIndex) -> graph::Edges<Edge<'a>, petgraph::Directed> {
        self.edges_directed(gadget, Direction::Incoming)
    }

    /// Iterator on the output edges of gadget.
    fn g_outputs(&self, gadget: NodeIndex) -> graph::Edges<Edge<'a>, petgraph::Directed> {
        self.edges_directed(gadget, Direction::Outgoing)
    }

    /// Get the gadget with the given node index. (Panics on error.)
    fn gadget(&self, idx: NodeIndex) -> &GadgetNode<'a, 'b> {
        if let GFNode::Gadget(ref gadget) = &self[idx] {
            gadget
        } else {
            panic!("Gadget at index {:?} is not a gadget.", idx)
        }
    }

    /// Show an edge
    fn disp_edge(&self, e: petgraph::graph::EdgeReference<Edge<'a>>) -> String {
        format!(
            "from {:?} to {:?}, {:?}",
            self[e.source()],
            self[e.target()],
            e.weight()
        )
    }
}

impl<'a, 'b> GadgetFlow<'a, 'b> {
    /// Iterator of the ids of the gadgets in the graph.
    pub fn gadget_names<'s>(&'s self) -> impl Iterator<Item = Name<'a>> + 's {
        self.ggraph.gadgets().map(|(_, g)| g.name)
    }

    fn build_graph(
        ggraph: &mut Graph<GFNode<'a, 'b>, Edge<'a>>,
        internals: &gadget_internals::GadgetInternals<'a, 'b>,
        n_cycles: Latency,
    ) -> CResult<'a, (HashMap<Name<'a>, NodeIndex>, NodeIndex)> {
        let i_nodes = (0..n_cycles)
            .map(|lat| ggraph.add_node(GFNode::Input(lat)))
            .collect::<Vec<_>>();
        let o_node = ggraph.add_node(GFNode::Output);
        let inv_node_in = ggraph.add_node(GFNode::Invalid);
        let inv_node_out = ggraph.add_node(GFNode::Invalid);
        let mut g_nodes = HashMap::new();
        for (name, sgi) in internals.subgadgets.iter() {
            for lat in 0..n_cycles {
                let g = ggraph.add_node(GFNode::Gadget(GadgetNode {
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
                    ggraph.add_edge(
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
                ggraph.add_edge(
                    src_g,
                    o_node,
                    Edge {
                        output: src_o,
                        input: (*output, cycle),
                    },
                );
            }
        }
        for (name, sgi) in internals.subgadgets.iter() {
            for cycle in 0..n_cycles {
                let node = g_nodes[&(*name, cycle)];
                let present_outputs = ggraph
                    .edges_directed(node, Direction::Outgoing)
                    .map(|e| e.weight().output)
                    .collect::<HashSet<_>>();
                for output in sgi.kind.outputs.keys() {
                    if !present_outputs.contains(&output) {
                        // output missing: it is not used in any gadget in the valid time range
                        ggraph.add_edge(
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
        return Ok((g_nodes, o_node));
    }

    /// Build (non-annotated) a GadgetFlow graph from the GadgetInternals, for n_cycles execution
    /// cycles.
    pub fn new(
        internals: gadget_internals::GadgetInternals<'a, 'b>,
        n_cycles: Latency,
        controls: &mut clk_vcd::ModuleControls,
    ) -> CResult<'a, Self> {
        let mut ggraph = Graph::new();
        let (g_nodes, o_node) = Self::build_graph(&mut ggraph, &internals, n_cycles)?;
        let ggraph = GGraph(ggraph);
        let muxes_ctrls = mux_ctrls(ggraph.gadgets(), controls)?;
        let sorted_nodes = Self::toposort(&ggraph, &internals, &muxes_ctrls)?;
        let (edge_validity, edge_sensitivity) =
            Self::annotate(&ggraph, &internals, &muxes_ctrls, &sorted_nodes)?;
        let res = Self {
            internals,
            ggraph,
            g_nodes,
            n_cycles,
            o_node,
            muxes_ctrls,
            edge_validity,
            edge_sensitivity,
        };
        return Ok(res);
    }

    /// Filter out inputs of muxes that are not selected
    fn mux_filterer(
        edge_ref: EdgeReference<Edge<'a>>,
        muxes_ctrls: &HashMap<NodeIndex, Option<bool>>,
    ) -> bool {
        match (
            muxes_ctrls.get(&edge_ref.target()),
            edge_ref.weight().input.0.port_name,
        ) {
            (Some(Some(true)), "in_false") | (Some(Some(false)), "in_true") => false,
            _ => true,
        }
    }

    /// Sort the nodes in the graph, inputs first.
    /// Does not take into account the non-selected edge of a mux for the ordering.
    /// Err if there is a cycle in the graph.
    fn toposort(
        ggraph: &GGraph<'a, 'b>,
        internals: &gadget_internals::GadgetInternals<'a, 'b>,
        muxes_ctrls: &HashMap<NodeIndex, Option<bool>>,
    ) -> CResult<'a, Vec<NodeIndex>> {
        let fggraph = EdgeFiltered::from_fn(&ggraph.0, |edge_ref| {
            Self::mux_filterer(edge_ref, muxes_ctrls)
        });
        Ok(petgraph::algo::toposort(&fggraph, None).map_err(|cycle| {
            CompError::ref_nw(
                &internals.gadget.module,
                CompErrorKind::Other(format!(
                    "Looping data depdendency containing gadget {:?}",
                    ggraph[cycle.node_id()]
                )),
            )
        })?)
    }

    /// Compute validity and sensitivity information for each edge.
    fn annotate(
        ggraph: &GGraph<'a, 'b>,
        internals: &gadget_internals::GadgetInternals<'a, 'b>,
        muxes_ctrls: &HashMap<NodeIndex, Option<bool>>,
        sorted_nodes: &[NodeIndex],
    ) -> Result<(Vec<bool>, Vec<Sensitive>), CompError<'a>> {
        let mut edges_valid: Vec<Option<bool>> = vec![None; ggraph.edge_count()];
        let mut edges_sensitive: Vec<Option<Sensitive>> = vec![None; ggraph.edge_count()];
        for idx in sorted_nodes.into_iter() {
            match &ggraph[*idx] {
                GFNode::Gadget(_) => {
                    let max_output = ggraph.g_outputs(*idx).map(|e| e.weight().output.pos).max();
                    if let (Some(ctrl), Some(max_output)) = (muxes_ctrls.get(idx), max_output) {
                        //let mut outputs: Vec<bool> = vec![false; max_output as usize + 1];
                        let mut outputs_valid: Vec<Option<bool>> =
                            vec![None; max_output as usize + 1];
                        let mut outputs_sensitive: Vec<Option<Sensitive>> =
                            vec![None; max_output as usize + 1];
                        if let Some(ctrl) = ctrl {
                            let input = if *ctrl { "in_true" } else { "in_false" };
                            for e_i in ggraph.g_inputs(*idx) {
                                let Sharing { port_name, pos } = &e_i.weight().input.0;
                                if port_name == &input {
                                    outputs_valid[*pos as usize] = edges_valid[e_i.id().index()];
                                    // Neglect glitches for now, will come to it later
                                    outputs_sensitive[*pos as usize] =
                                        edges_sensitive[e_i.id().index()];
                                }
                            }
                        } else {
                            for e_i in ggraph.g_inputs(*idx) {
                                let Sharing { pos, .. } = &e_i.weight().input.0;
                                if *pos > max_output {
                                    panic!(
                                        "pos: {}, max_output (): {}, name: {:?}, base: {:?}\noutputs:{:?}",
                                        *pos,
                                        max_output,
                                        ggraph[*idx],
                                        ggraph.gadget(*idx).base.kind,
                                        ggraph.g_outputs(*idx).collect::<Vec<_>>()
                                    );
                                }
                                outputs_valid[*pos as usize] = Some(false);
                                let sens_new = edges_sensitive[e_i.id().index()].unwrap();
                                let sens =
                                    outputs_sensitive[*pos as usize].get_or_insert(Sensitive::No);
                                *sens = (*sens).max(sens_new);
                            }
                        }
                        for o_e in ggraph.g_outputs(*idx) {
                            let pos = o_e.weight().output.pos as usize;
                            edges_valid[o_e.id().index()] = outputs_valid[pos];
                            edges_sensitive[o_e.id().index()] = outputs_sensitive[pos];
                        }
                    } else {
                        let g_valid = ggraph.g_inputs(*idx).all(|e| {
                            edges_valid[e.id().index()].unwrap_or_else(|| {
                                panic!(
                                "Non-initialized validity for edge {}, src node pos: {:?}, target node pos: {:?}",
                                ggraph.disp_edge(e),
                                sorted_nodes.iter().find(|x| **x== e.source()),
                                sorted_nodes.iter().find(|x| **x == e.target()),
                            );})
                        });
                        let g_sensitive = ggraph
                            .g_inputs(*idx)
                            .map(|e| {
                                edges_sensitive[e.id().index()]
                                    .expect("Non-initialized sensitivity")
                            })
                            .max()
                            .unwrap_or(Sensitive::No);
                        for e in ggraph.g_outputs(*idx) {
                            edges_valid[e.id().index()] = Some(g_valid);
                            edges_sensitive[e.id().index()] = Some(g_sensitive);
                        }
                    }
                }
                GFNode::Input(lat) => {
                    for e in ggraph.g_outputs(*idx) {
                        let Edge { output, .. } = e.weight();
                        let valid = internals.gadget.inputs[output].contains(&lat);
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
                    assert!(ggraph.g_outputs(*idx).next().is_none());
                }
                GFNode::Invalid => {
                    // Connections from non-existing gadgets or out of range inputs.
                    // Assume that they are non-sensitive (might want to assume glitch ?)
                    for e in ggraph.g_outputs(*idx) {
                        edges_valid[e.id().index()] = Some(false);
                        edges_sensitive[e.id().index()] = Some(Sensitive::No);
                    }
                }
            }
            for e in ggraph.g_outputs(*idx) {
                assert!(
                    edges_valid[e.id().index()].is_some(),
                    "Failed init valid for edge {}",
                    ggraph.disp_edge(e)
                );
                assert!(
                    edges_sensitive[e.id().index()].is_some(),
                    "Failed init sensitive for edge {}",
                    ggraph.disp_edge(e)
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
        let mut gl_to_analyze = ggraph.gadgets().map(|x| x.0).collect::<BinaryHeap<_>>();
        while let Some(idx) = gl_to_analyze.pop() {
            let noglitch_cycle = compute_sensitivity(
                ggraph
                    .g_inputs(idx)
                    .map(|e| (edges_sensitive[e.id().index()], e.weight().input)),
            );
            if noglitch_cycle == 0 {
                continue;
            }
            for e in ggraph.g_outputs(idx) {
                if edges_sensitive[e.id().index()] == Sensitive::No {
                    let output_lat = *ggraph
                        .gadget(idx)
                        .base
                        .kind
                        .outputs
                        .get(&e.weight().output)
                        .unwrap();
                    if output_lat < noglitch_cycle {
                        edges_sensitive[e.id().index()] = Sensitive::Glitch;
                        if ggraph[e.target()].is_gadget() {
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

    fn edge_valid(&self, e: EdgeReference<Edge<'a>>) -> bool {
        self.edge_validity[e.id().index()]
    }

    fn edge_sensitive(&self, e: EdgeReference<Edge<'a>>) -> Sensitive {
        self.edge_sensitivity[e.id().index()]
    }

    /// Is the gadget n valid, that is, are all the inputs of node n valid ?
    fn gadget_valid(&self, n: NodeIndex) -> bool {
        self.ggraph.g_inputs(n).all(|e| self.edge_valid(e))
    }

    fn gadget_sensitivity(&self, n: NodeIndex) -> Sensitive {
        self.ggraph
            .g_inputs(n)
            .map(|e| self.edge_sensitive(e))
            .max()
            .unwrap_or(Sensitive::No)
    }

    /// Is the gadget n sensitive, that is, is any of the inputs of node n sensitive (in the
    /// glitch or non-glitch domain) ?
    pub fn gadget_sensitive(&self, n: NodeIndex) -> bool {
        self.gadget_sensitivity(n) != Sensitive::No
    }

    /// Is the gadget n sensitive, that is, is any of the inputs of node n sensitive (in the
    /// non-glitch domain) ?
    fn gadget_sensitive_stable(&self, n: NodeIndex) -> bool {
        self.gadget_sensitivity(n) == Sensitive::Yes
    }

    /// List the latencies at which each gadget is valid.
    pub fn list_valid(&self) -> HashMap<GName<'a>, Vec<Latency>> {
        let mut gadgets = HashMap::new();
        for (id, gadget) in self.ggraph.gadgets() {
            if gadget.base.kind.prop != netlist::GadgetProp::Mux {
                if self.gadget_valid(id) {
                    gadgets
                        .entry(gadget.name.0)
                        .or_insert_with(Vec::new)
                        .push(gadget.name.1);
                } else {
                    gadgets.entry(gadget.name.0).or_insert_with(Vec::new);
                }
            }
        }
        for cycles in gadgets.values_mut() {
            cycles.sort_unstable();
        }
        gadgets
    }

    /// List the latencies at which each gadget is sensitive.
    pub fn list_sensitive(&self, sensitivity: Sensitive) -> HashMap<GName<'a>, Vec<Latency>> {
        let mut gadgets = HashMap::new();
        for (id, gadget) in self.ggraph.gadgets() {
            if gadget.base.kind.prop != netlist::GadgetProp::Mux
                && self.gadget_sensitivity(id) == sensitivity
            {
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
        self.ggraph
            .gadgets()
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
        for (id, gadget) in self.ggraph.gadgets() {
            println!("Gadget {:?}:", gadget.name);
            println!("Inputs:");
            for e in self.ggraph.g_inputs(id) {
                let input = e.weight().input;
                println!(
                    "\tinput ({}[{}], {}): Valid: {:?}, Sensitive: {:?}",
                    input.0.port_name,
                    input.0.pos,
                    input.1,
                    self.edge_valid(e),
                    self.edge_sensitive(e)
                );
            }
            for e in self.ggraph.g_outputs(id) {
                let output = e.weight().output;
                println!(
                    "\toutput {}[{}]: Valid: {:?}, Sensitive: {:?}",
                    output.port_name,
                    output.pos,
                    self.edge_valid(e),
                    self.edge_sensitive(e)
                );
            }
        }
    }

    /// Checks that all the inputs are valid when the should be valid according to specification.
    pub fn check_valid_outputs(&self) -> CResult<'a, ()> {
        let valid_outputs = self
            .ggraph
            .g_inputs(self.o_node)
            .filter_map(|e| {
                if self.edge_valid(e) {
                    Some(e.weight().input)
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
            .ggraph
            .g_inputs(self.o_node)
            .filter_map(|e| {
                // We don't care about glitches, those are inferred and always assumed by the
                // outside world.
                if self.edge_sensitive(e) == Sensitive::Yes {
                    let (sh, lat) = e.weight().input;
                    if let Some(l) = self.internals.gadget.outputs.get(&sh) {
                        if *l != lat {
                            return Some((sh, lat, Some(*l)));
                        }
                    } else {
                        return Some((sh, lat, None));
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
            vec![HashMap::new(); self.ggraph.node_count()];
        let mut name_cache = HashMap::new();
        let mut errors: Vec<CompError<'a>> = Vec::new();
        println!("starting randoms_input_timing");
        let mut i = 0;
        for (idx, gadget) in self.ggraph.gadgets() {
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
                            let gadget = self.ggraph.gadget(*idx);
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
                    let GadgetNode { name, .. } = self.ggraph.gadget(uses[0].0);
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
            .map(|(rnd, lat)| {
                if is_rnd_valid(&self.internals.gadget, rnd, *lat, controls)? {
                    Ok(())
                } else {
                    Err(CompError::other(
                        &self.internals.gadget.module,
                        rnd.port_name,
                        &format!(
                            "Random input {} is used at cycle {} while not valid at that cycle.",
                            rnd, lat
                        ),
                    ))
                }
            })
            .filter_map(Result::err)
            .collect::<Vec<_>>();
        CompErrors::result(errors)
    }

    /// Verifies that there is no any more sensitive state in the circuit after n_cycles.
    pub fn check_state_cleared(&self) -> CResult<'a, ()> {
        let max_out_lat = self.internals.gadget.max_output_lat();
        let errors = self
            .ggraph
            .gadgets()
            .filter(|(idx, _)| self.gadget_sensitive_stable(*idx)) // ok: we don't care about glitches
            .flat_map(|(idx, gadget)| {
                self.ggraph.g_outputs(idx).filter_map(move |e| {
                    let out_lat = gadget.base.kind.outputs[&e.weight().output];
                    if gadget.name.1 + out_lat > max_out_lat {
                        Some(CompError::ref_nw(
                            &self.internals.gadget.module,
                            CompErrorKind::LateOutput(
                                max_out_lat,
                                gadget.name.1,
                                out_lat,
                                (*gadget.name.0.get()).to_owned(),
                                e.weight().output,
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
    pub fn sensitive_stable_gadgets<'s>(
        &'s self,
    ) -> impl Iterator<Item = (Name<'a>, &'s gadget_internals::GadgetInstance<'a, 'b>)> + 's {
        self.ggraph
            .gadgets()
            .filter(move |(idx, _)| self.gadget_sensitive_stable(*idx))
            .map(|(_, g)| (g.name, &g.base))
    }

    fn build_contiguous_seq_gadget(&self, name: GName<'a>) -> Vec<(Latency, Latency)> {
        let mut last_start = None;
        let mut lat_iter = (0..self.n_cycles).into_iter();
        std::iter::from_fn(move || {
            while let Some(lat) = lat_iter.next() {
                let n = self.g_nodes[&(name, lat)];
                match self.gadget_sensitivity(n) {
                    Sensitive::No => {
                        if let Some(ls) = last_start {
                            last_start = None;
                            return Some((ls, lat - 1));
                        }
                    }
                    Sensitive::Glitch => {
                        if let Some(ls) = last_start {
                            last_start = None;
                            return Some((ls, lat));
                        }
                    }
                    Sensitive::Yes => {
                        if last_start.is_none() {
                            last_start = Some(lat);
                        }
                    }
                }
            }
            if let Some(ls) = last_start {
                last_start = None;
                return Some((ls, self.n_cycles - 1));
            }
            return None;
        })
        .collect()
    }

    fn list_non_affine_gadgets(&self) -> Vec<GName<'a>> {
        self.internals
            .subgadgets
            .iter()
            .filter(|(_, inst)| !inst.kind.prop.is_affine())
            .map(|(gname, _)| *gname)
            .collect()
    }

    /// For a given structural gadget and an inclusive range [start, end] of latencies,
    /// try to find a (lat0, lat1) pair such that the instance at latency lat1 has an input that
    /// depends of an ouput of the instance at latency lat0.
    fn seq_gadgets_parallel(
        &self,
        name: GName<'a>,
        start: Latency,
        end: Latency,
    ) -> Option<(Latency, Latency)> {
        // gadgets with latency > end cannot reach end.
        let fgraph = petgraph::visit::NodeFiltered(&self.ggraph.0, |node_id| {
            if let GFNode::Gadget(gn) = &self.ggraph[node_id] {
                gn.name.1 <= end
            } else {
                false
            }
        });
        let fgraph = EdgeFiltered::from_fn(&fgraph, |edge_ref| {
            Self::mux_filterer(edge_ref, &self.muxes_ctrls)
        });
        let mut dfs = petgraph::visit::Dfs::empty(&fgraph);
        for lat in start..end {
            dfs.move_to(self.g_nodes[&(name, lat)]);
            while let Some(nx) = dfs.next(&fgraph) {
                if let Some(fail_lat) = self.ggraph[nx]
                    .gadget()
                    .filter(|gn| gn.name.0 == name)
                    .map(|gn| gn.name.1)
                    .filter(|l| *l <= end && *l != lat)
                {
                    return Some((lat, fail_lat));
                }
            }
        }
        return None;
    }

    /// Incomplete list if non-empty !
    fn list_non_parllel_seq_gadgets(&self) -> Vec<(Name<'a>, Latency)> {
        let mut res = vec![];
        for name in self.list_non_affine_gadgets() {
            for (start, end) in self.build_contiguous_seq_gadget(name) {
                if let Some((fail_lat_s, fail_lat_e)) = self.seq_gadgets_parallel(name, start, end)
                {
                    res.push(((name, fail_lat_s), fail_lat_e));
                }
            }
        }
        return res;
    }

    pub fn check_parallel_seq_gadgets(&self) -> CResult<'a, ()> {
        let errors = self.list_non_parllel_seq_gadgets().into_iter().map(|(name, follower)| {
            CompError::ref_nw(
                &self.internals.gadget.module,
                CompErrorKind::Other(
                    format!(
                        "PINI Gadget {} is sensitive at all cycles between {} and {} (included), and input of execution {} depends on output of execution {}, which breaks transition-robust security.",
                        name.0, name.1, follower, follower, name.1
                    )
                )
            )
        }).collect::<Vec<_>>();
        CompErrors::result(errors)
    }
}

pub fn is_rnd_valid<'a>(
    gadget: &gadgets::Gadget<'a>,
    rnd: &gadgets::Random<'a>,
    lat: Latency,
    controls: &mut clk_vcd::ModuleControls,
) -> Result<bool, CompError<'a>> {
    match &gadget.randoms[rnd] {
        Some(RndLatencies::Attr(lats)) => Ok(lats.contains(&lat)),
        Some(RndLatencies::Wire { wire_name, offset }) => {
            let cycle = <u32 as std::convert::TryFrom<i32>>::try_from((lat as i32) + offset)
                .map_err(|_| {
                    CompError::other(
                        &gadget.module,
                        rnd.port_name,
                        &format!(
                            "For random at cycle {}, control signal cycle is negative (offset: {})",
                            lat, offset
                        ),
                    )
                })?;
            let valid = controls
                .lookup(vec![wire_name.clone()], cycle as usize, 0)?
                .and_then(|var_state| var_state.to_bool())
                .ok_or_else(|| {
                    CompError::other(
                        &gadget.module,
                        rnd.port_name,
                        &format!(
                            "Valid-indicating wire has no value at cycle {} (for rnd at cycle {})",
                            cycle, lat
                        ),
                    )
                })?;
            Ok(valid)
        }
        None => Err(CompError::ref_sn(
            &gadget.module,
            rnd.port_name,
            CompErrorKind::Other(
                "Sub-gadget randomness inputs must be annotated with the 'fv_latency' attribute"
                    .to_string(),
            ),
        )),
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
    i_nodes: &[NodeIndex],
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
