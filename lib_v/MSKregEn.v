(* fv_strat = "flatten" *)
module MSKregEn #(parameter d=1, parameter count=1) (clk, en, in, out);

(* fv_type = "clock" *)   input clk;
(* fv_type = "control" *) input en;
(* fv_type = "sharing", fv_latency = 0, fv_count=count *) input  [count*d-1:0] in;
(* fv_type = "sharing", fv_latency = 1, fv_count=count *) output [count*d-1:0] out;

wire [count*d-1:0] reg_in;

MSKmux #(.d(d), .count(count)) mux (.sel(en), .in_true(in), .in_false(out), .out(reg_in));
MSKreg #(.d(d), .count(count)) state_reg (.clk(clk), .in(reg_in), .out(out));

endmodule
