(* psim_strat = "flatten" *)
module MSKregEn #(parameter d=1, parameter count=1) (clk, en, in, out);

(* psim_type = "clock" *)   input clk;
(* psim_type = "control" *) input en;
(* psim_type = "sharing", psim_latency = 0, psim_count=count *) input  [count*d-1:0] in;
(* psim_type = "sharing", psim_latency = 1, psim_count=count *) output [count*d-1:0] out;

wire [count*d-1:0] reg_in;

MSKmux #(.d(d), .count(count)) mux (.sel(en), .in_true(in), .in_false(out), .out(reg_in));
MSKreg #(.d(d), .count(count)) state_reg (.clk(clk), .in(reg_in), .out(out));

endmodule
