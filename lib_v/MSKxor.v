(* psim_prop = "affine", psim_strat = "assumed", psim_order = d *)
module MSKxor #(parameter d=1, parameter count=1) (ina, inb, out);

(* psim_type = "sharing", psim_latency = 0, psim_count=count *) input  [count*d-1:0] ina, inb;
(* psim_type = "sharing", psim_latency = 0, psim_count=count *) output [count*d-1:0] out;

assign out = ina ^ inb ;

endmodule
