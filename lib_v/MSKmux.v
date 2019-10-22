(* psim_prop = "_mux", psim_strat = "assumed", psim_order = d *)
module MSKmux #(parameter d=1, parameter count=1) (sel, in_true, in_false, out);

(* psim_type = "control" *) input sel;
(* psim_type = "sharing", psim_latency = 0, psim_count=count *) input  [count*d-1:0] in_true;
(* psim_type = "sharing", psim_latency = 0, psim_count=count *) input  [count*d-1:0] in_false;
(* psim_type = "sharing", psim_latency = 0, psim_count=count *) output [count*d-1:0] out;

assign out = sel ? in_true : in_false;

endmodule
