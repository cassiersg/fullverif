(* psim_prop = "affine", psim_strat = "assumed", psim_order = d *)
module MSKinv #(parameter d=2, parameter count=1) (in, out);

(* psim_type = "sharing", psim_latency = 0, psim_count=count *) input  [count*d-1:0] in;
(* psim_type = "sharing", psim_latency = 0, psim_count=count *) output [count*d-1:0] out;

genvar i;
generate
for(i=0; i<count; i=i+1) begin: inv
    assign out[i*d] = ~in[i*d];
    if (d > 1) begin
        assign out[i*d+1 :+ d-1] = in[i*d+1 +: d-1];
    end
end
endgenerate

endmodule
