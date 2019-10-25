(* psim_prop = "affine", psim_strat="isolate", psim_order=d *)
module MSKreg #(parameter d=1, parameter count=1) (clk, in, out);

(* psim_type = "clock" *)   input clk;
(* psim_type = "sharing", psim_latency = 0, psim_count=count *) input  [count*d-1:0] in;
(* psim_type = "sharing", psim_latency = 1, psim_count=count *) output [count*d-1:0] out;

reg [count*d-1:0] state;

always @(posedge clk)
    state <= in;

assign out = state;

endmodule
