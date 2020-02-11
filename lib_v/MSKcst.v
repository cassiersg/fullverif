// Mask a non-sentitive variable x into a sharing (x, 0, ..., 0)
(* fv_prop = "affine", fv_strat = "isolate", fv_order = d *)
module MSKcst #(parameter d=1, parameter count=1) (cst, out);

(* fv_type = "control" *)       input [count-1:0] cst;
(* fv_type = "sharing", fv_count = count, fv_latency = 0 *) output [count*d-1:0] out;

genvar i;
for(i=0; i<count; i=i+1) begin: i_gen_m
    assign out[i*d +: d] = { cst[i], {(d-1){1'b0}}};
end

endmodule
