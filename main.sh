#! /bin/sh

# ./fullverif.sh . MSKclyde_128_1R tb_clyde_128_1R_UMSK

####### Settings #######

## Verilog source
# NB: we use the convention that module X is always in file X.v in this script

# Directory containing source verilog files needed for synthesis
export IMPLEM_DIR=$1
# Name of the main module to be checked
export MAIN_MODULE=$2
# Name of the testbench module
TB_MODULE=$3
# Directory containing verilog sources needed for simulation
SIMU_DIR=$IMPLEM_DIR
# signal starting the first simulation cycle (i.e. latency == 0 for the main module), name in the testbench
IN_VALID=start_dut
# clock signal (in the testbench)
CLOCK=clk
# name of the instance of the main module in the testbench
DUT=dut

## Tools location

SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

IV=/usr/local/bin/iverilog
VVP=/usr/local/bin/vvp
YOSYS_BIN=/usr/local/bin/yosys
# Change only if you did not install fullverif from sources or if you moved this script.
FULL_VERIF=$SCRIPTPATH/fullverif-check/target/release/fullverif
export FULLVERIF_LIB_DIR=$SCRIPTPATH/lib_v

## Where to put synthesis and simulation results

export OUT_DIR=`mktemp -d -t fullverif-XXXXXXXXXXXXXXXX`
echo "Temp files are written in $OUT_DIR"

VCD_PATH=$OUT_DIR/a.vcd
SIM_PATH=$OUT_DIR/a.out
SYNTH_BASE=$OUT_DIR/${MAIN_MODULE}_synth
TB_PATH=$SIMU_DIR/$TB_MODULE.v


####### Execution #######

echo "Starting synthesis..."
$YOSYS_BIN -q -c $FULLVERIF_LIB_DIR/../msk_presynth.tcl || exit
echo "Synthesis finished."

echo "Starting simulation..."
# Change this if you want to use another simulator
# -y source directory for .v modules
# -s top-level module (i.e. testbench)
# -D define VCD_PATH so that the testbench can write the vcd in the correct location
$IV -y $SIMU_DIR -y $FULLVERIF_LIB_DIR -I $SIMU_DIR -I $FULLVERIF_LIB_DIR -s $TB_MODULE -o $SIM_PATH -D VCD_PATH=\"$VCD_PATH\" $SYNTH_BASE.v $TB_PATH || exit
$VVP $SIM_PATH
echo "Simulation finished"

echo "Starting fullverif..."
$FULL_VERIF --json $SYNTH_BASE.json --vcd $VCD_PATH --tb $TB_MODULE --gname $MAIN_MODULE --in-valid $IN_VALID --clock $CLOCK --dut $DUT
#echo "fullverif finished."

