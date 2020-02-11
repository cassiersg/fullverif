
# fullVerif

fullVerif is a tool to analyze security of masked circuits at the composition
level: based on elementary gadgets that are assumed to be correct, this tool
checks that the larger composite circuit is secure by using a compositional
strategy (e.g.  based on PINI, SNI, NI).

For more background on compositional strategies for masked hardware
implementations, see [the paper](https://eprint.iacr.org/2020/TODO) on which
this tool is based.

## Principle

The tool analyzes the dataflow of masked sharings in the circuit and check that
it satifies the compositional strategy.
fullVerif takes Verilog code as input. In order to simplify its analysis, it
first simplifies it to and abstract netlist using the open-source synthesizer yosys.
To get the dataflow of a complex circuit with loops, the tool then simulates
(using the IcarusVerilog simulator) one execution of the circuit, which gives
it the values for all the control signals of the circuit (e.g. round counter,
muxes select, etc.).
Once those control signals are known, the dataflow can be computed and analyzed.

## Usage

### Build

**Dependencies**:
- `yosys >= 0.9` <http://www.clifford.at/yosys/>
- `iverilog >= 10.4` or git master <https://github.com/steveicarus/iverilog>
  (commit `f2ca63a5a110` has been tested)
- rust development toolchain (rustc, cargo) (`>=1.38`) <https://rustup.rs/>

**Build**
- `git clone https://github.com/cassiersg/fullverif.git`
- cd fullverif/fullverif-check
- `cargo build --release`

### Test (unix-like)

Assuming Yosys and Iverilog are installed in `/usr/local` (otherwise, edit the
script `fullverif.sh` accordingly).

- `git clone https://github.com/cassiersg/present_hpc.git`
- `./fullverif/main.sh present_hpc MSKpresent_encrypt tb_present_128`

### Custom run

The previous test section uses the `main.sh` shell script to automate the three
main steps of the tool:
- synthesis
- simulation
- analysis

This script can be adapted to suit other configurations, or the three steps can
be run in by any other mean.
In the following, we describe the steps.

**Synthesis** takes the design as input and must be performed by Yosys, using
the provided `msk_presynth.tcl` script. 
This outputs a netlist in two formats: a verilog and a json one.

**Simulation** takes the verilog netlist, a testbench and optionnally other
verilog files and outputs a vcd.
This can be done by any verilog simulator, although only Icarus Verilog has
been tested (and only the git master version is able to handle the annotations
we have in the code).

**Analysis** takes as input the json netlist, the vcd files, and a few
parameters describing the design.
It outputs a report.

If you intend to use this tool on other code than the provided examples, you
should read, in addition to this README, all the settings in the `main.sh`
script, since those must match the verilog code.
You might also find the output of the fullverif binary
(`fullverif/target/release/fullverif --help`) and the `lib_v/msk_presynth.tcl`
helpful.

## Design

In this section, we describe under what conditions the tool may sucessfully
analyze a design.


### Gadgets

Each gadget is implemented by a verilog module.
Once a gadget has been converted to a netlist, it is made of wires and modules.
Among those modules, we denote sub-gadgets (that is, modules which are
themselves gadgets), randomness manipulation gates, and control modules.
The randomness distribution gates are the modules that manipulate values coming
from the randomness input of the gadgets, they must be either flip-flops or muxes.
The control modules are the remaining part of the logic, which can impact the
two other parts through control signal (for muxes, e.g.).
Those control signal are not symbolically analized by the tool, instead their
value is obtained thanks to the simulation.

The main datapath of a gadget is thus made of sub-gadgets, whose input and
output sharings are interconnected (and connected to the input and output
sharings of the gadget).
The analysis of the randomness distribution happens symbolically for flip-flops
and muxes: fullverif assumes that a fresh random bit is present on each of its
randomenss inputs at each cycles and computes how these bits propagate to
inputs of sub-gadgets, deducing which ones are needed.

### Annotations

We use verilog annotations to convey informations about the masking scheme to
fullVerif.
For each gadget, the following annotation are required on the module itself:
+ `fv_order` (*int*): specifies the number of shares of the masking.
+ `fv_prop` (*string*): gives the security property satisfied by this module. The
  following properties are understood: `PINI`, `NI`, `SNI`, `affine` (for
  gadget which preserve strict isolation of shares).
+ `fv_strat` (*string*): strategy for proving this module.
    * `"assumed"`: the tool will perform no check on the gadget (typically used
      for gadgets whose implementation has been checked either manually or
      using another tool),
    * `"composite"`: the tool will check the gadget using a compositional
      strategy, and will recursively check any sub-gadget instantiated inside
      the gadget.
    * `"flatten"`: this module will be flattened during verilog synthesis and
      will thus not be analyzed by itself (its components will be analyzed as
      part of the modules in which it is instantiated). Therefore, no other
      annotation is required on this module or on its ports.
    * `"isolate"`: this strategies only applies to gadgets whose property is
      `affine`, and makes a topological check that the gadget is a "trivial
      implementation": any output share of the gadget must only be wired to the
      corresponding input shares.

All the ports of the module also have to be annotated using the `fv_type`
attribute, which may have any of the four following values:
+ `"sharing"`: denotes an input or output sharing (depending on the direction of
        the port). The `fv_latency` attribute is required (see below).
The optional `fv_count` attribute denotes the number of sharings
contained into the sharing (defaults to 1).
The width of the port must be `fv_count*fv_order`, and the share of one
sharing must be packed together (i.e., the first sharing is `port[0 +: d]`, the
second is `port[d +: d]`... where `d` is the number of shares).
+ `"clock"`: The must be at most one input clock signal (whose width must be 1).
+ `"control"`: A port which is not analyzed by the tool.
+ `"random"`: Randomness input used for masked gadgets.
Each randomness port must specify its latency, this is done by first splitting
the input into contiguous chunks of bits (starting at bit 0), where the size of
chunk `i` is `fv_rnd_count_{i}`.
The number of chunks must be given in the `fv_count` attribute.
The latency for chunk `i` is given in attribute `fv_rnd_lat_{i}`.
Chunks may be valid at more than one clock cycle. This is specified by
using the `fv_rnd_lats_{i}` attribute in place of the `fv_rnd_lat_{i}` attribute;
the semantic of its value is identical to the that of the `fv_latencies`
attribute of input sharings (see below).
For the top-level module, all chunks and latency information may not be
provided by setting `fv_count=0`, in which case random latencies are
inferred.
For the top-level module, instead of `fv_rnd_lat(s)_{i}`, the latencies may be specified by means of a signal in the module.
The randomness is considered valid for all cycles `c` that satisfy the
following condition: the signal denoted in the attribute `fv_en_{i}` is
asserted at the cycle `c+o`, where `o` is the value of the `fv_en_offset_{i}`
attribute.

*Latency specification.* The latency is given for input and output sharings and
randomness in number of clock cycles.
For each module, all latencies must be postitive integers.
Input sharings may be valid at more than one clock cycle. This is specified by
using the `fv_latencies` attribute in place of the `fv_latency` attribute.
The value of the `fv_latencies` attribute must be a positive integer.
Let `bi` be the `i`-th bit of the binary decomposition of that value, with `b0`
the LSB. The input is valid at cycle `i` iff `bi` is 1.


### Structure of fullverif (analysis phase)

#### Composite strategy

In the first stage, fullverif lists the gadgets from the netlist, and reads
their ports to construct an abstract representation of their interface.

In the second stage, fullverif takes the main gadget (as specified on the
command-line) and analyzes its internals: it lists all the sub-gadgets, their
interconnects, the randomness distribution, and the input/output connections.
At this stage, only the netlist is used, hence nothing is known about the
control signals.
However, some checks can already be performed, such as checking that all
sharings are properly generated and only used as inputs sharings of other
gadgets.
(Therefore, standard verilog constructs such as conditional statements,
ternary operator or arithmetic operations cannot be used on sharings at the
level of a composite gadget.)

In the third stage, the sequential nature of the circuit starts to be taken
into account: each sub-gadget from the netlist is instantiated into a distinct
gadget for each cycle of the computation (from the "valid in" signal until all
outputs are computed).
Then, those new gadgets are interconnected, taking the "latency" information
into account.
From there on, the sub-gadget graph corresponds more to a computation graph
than to a physical netlist, and we call it a "GadgetFlow" graph.
Then, the following computations are performed on the GadgetFlow graph:
* Each edge of the graph is annotated with validity and sensitivity information.
An edge is valid if it carries a sharing of a variable that depends on the
inputs of the circuit (and not on the initial state of the circuit, which is
considered to be invalid).
An edge is sensitive if the share it carries depend on the input sharings of
the gadget. (The edge may also by glitch-sensitive: its value is non-sensitive
but there may be glitches that depend on sensitive variable).
A gadget is valid if all its inputs are valid, and it is sensitive if any of
its inputs is sensitive.
This step makes a special treatment of muxes in order to compute the validity
and sensitivity of their outputs.
The validity sensitivity of each and gadget is shown for each cycle.
This requires knowledge of the control signals of the muxes, which are
extracted from the result of the simulation.
* It is checked that the output sharings are valid when the annotations specify
  the they should be valid. 
* The randomness usage of each subgadget is traced back (when it is sensitive)
  to the randomness input of the gadget. It is checked that a fresh random bit
  needed for a subgadget is not used elsewhere.
  The list of input random bits used is reported for each cycle and checked
  against the annotation (if present).
  The randomness bits tracking is able to handle muxes and registers, but
  forbids any other gate.
* It is checked that after the last execution cycle, no sensitive state remains
  in the circuit in order to prevent unintended leakage from happening
  afterwards.

The fourth stage actually verifies the abstract composition strategy, based on
the GadgetFlow graph (e.g. "Are all sub-gadgets PINI ?").

Finally, steps 2 to 4 are repeated for each sub-gadget for which the strategy
is "composite", and the steps are performed for each set of sequences of
control values in the gadget (the relevant control values are those that are
used to analyze how muxes behave).

#### Isolate strategy

For gadgets where the strategy is "isolate", it is checked that they can be
split into `d` sub-circuits, one for each share, such that there is no
interconnection of shares or randomness between the sub-circuits.

### Testbench

The testbench must exercise a standard behavior of one execution of the main
module, which it should instantiate.
There should be a startup signal (whose name can be set in the `main.sh`
script) that should raise to `1` to signal the cycle '0' w.r.t. the latency
annotations in the main module.
Name of the main module instance and clock signal can be set in `main.sh`.

The input sharings and randomness are not important (can be any value,
including `x` or `z`).

### Gadget libarry

Fullverif comes with a library of basic gadgets in `lib_v`, implementing functionalities such as:

Linear and affine gates:
- mux ('MSKmux.v`)
- flip-flop (`MSKreg.v`)
- XOR (`MSKxor.v`)
- NOT (`MSKinv.v`)

Non-linear gate:
- PINI AND (`MSKand_HPC1.v`)
- PINI AND (`MSKand_HPC1.v`)
- DOM (NI) AND (`MSKand_DOM.v`)

Other:
- Masking a non-sensitive value (`MSKcst.v`). Note: The encoding does not
  need randomness since the value itself originally not masked and therefore
  not sensitive.
- SNI refresh (`MSKref.v`)

### Preventing damaging synthesis optimizations

The fullverif tool cannot guarantee that its output netlist will be protected
against optimizations that could break the security if it is fed to other tools
such as synthesizers.

This is mainly due to a lack of standard way of describing this requirement in
the HDL code.
However, the usage of the provided gadget library may help, by reducing the
concerns to the modules contained inside that library: all the other modules
that manipulate sharings do so only with wiring, which optimizers should not
have adversarial behavior.
We advise to disable as much as possible optimizations that remove, simplify or
re-time logic for gagdets of the library.
In order to ease this, we added `(* syn_keep="true", keep="true" *)` attributes
on sensitive `wire`s and `(* syn_preserve="true", preserve="true" *)` on
sensitive `reg`s.

Any suggestion on how to handle this in a better way is welcome.

## Bugs, contributing, etc.

Fullverif is an actively maintained software.
You are welcome to report bugs, submit enhancements proposals or code on
github, or by e-mail (to the contact author of the paper linked above).

## License

The Fullverif tool is primarily distributed under the terms of the GPL3 license.
The verilog library (`lib_v/`) is primarily distributed under the terms of both
the MIT license and the Apache License (Version 2.0).

See [LICENSE-GPL3](LICENSE-GPL3), [LICENSE-APACHE](LICENSE-APACHE),
[LICENSE-MIT](LICENSE-MIT), and [COPYRIGHT](COPYRIGHT) for details.


## Fullverif-check code overview

- `clk_vcd.rs`: Parsing of `vcd` files and representation as a sequence of
  states at each clock cycles.
- `netlist.rs`: Parsing of yosys `json` files and of verilog annotations.
- `gadgets.rs`: Interface of a gadget from the module ports and verilog annotations.
- `gadget_internals.rs`: Representation of a composite gadget as a graph of
  sub-gadgets and randomness distribution circuit.
- `tg_graph.rs`: "Unrolling" of a gadget over time, resulting in a
  computation graph. Analysis of control signals and simplification.
- `comp_prop.rs`: checking of the compositional strategy based on the
  computation graph.
