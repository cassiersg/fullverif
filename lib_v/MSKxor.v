(* fv_prop = "affine", fv_strat = "isolate", fv_order = d *)
module MSKxor #(parameter d=1, parameter count=1) (ina, inb, out);

(* fv_type = "sharing", fv_latency = 0, fv_count=count *) input  [count*d-1:0] ina, inb;
(* fv_type = "sharing", fv_latency = 0, fv_count=count *) output [count*d-1:0] out;

assign out = ina ^ inb ;

endmodule
