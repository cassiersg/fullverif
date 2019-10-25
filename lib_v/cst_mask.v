(* psim_prop = "affine", psim_strat = "isolate", psim_order = d *)
module cst_mask #(parameter d=1, parameter count=1) (cst, out);

	(* psim_type = "control" *)       input [count-1:0] cst;
	(* psim_type = "sharing", psim_count = count, psim_latency = 0 *) output [count*d-1:0] out;

	genvar i;
	for(i=0; i<count; i=i+1) begin: i_gen_m
		assign out[i*d +: d] = { cst[i], {(d-1){1'b0}}};
	end

endmodule
