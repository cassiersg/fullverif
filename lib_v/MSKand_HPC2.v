(* fv_prop = "PINI", fv_strat = "assumed", fv_order=d *)
module MSKand_HPC2 #(parameter d=2) (ina, inb, rnd, clk, out);

`include "MSKand_HPC2.vh"

(* syn_keep = "true", keep = "true", fv_type = "sharing", fv_latency = 1 *) input  [d-1:0] ina;
(* syn_keep = "true", keep = "true", fv_type = "sharing", fv_latency = 0 *) input  [d-1:0] inb;
(* syn_keep = "true", keep = "true", fv_type = "random", fv_count = 1, fv_rnd_lat_0 = 0, fv_rnd_count_0 = and_pini_nrnd *) input [and_pini_nrnd-1:0] rnd;
(* fv_type = "clock" *) input clk;
(* syn_keep = "true", keep = "true", fv_type = "sharing", fv_latency = 2 *) output [d-1:0] out;

genvar i,j;

// unpack vector to matrix --> easier for randomness handling
reg [and_pini_nrnd-1:0] rnd_prev;
always @(posedge clk) rnd_prev <= rnd;

wire [d-1:0] rnd_mat [d-1:0]; 
wire [d-1:0] rnd_mat_prev [d-1:0]; 
for(i=0; i<d; i=i+1) begin: igen
    assign rnd_mat[i][i] = 0;
    assign rnd_mat_prev[i][i] = 0;
    for(j=i+1; j<d; j=j+1) begin: jgen
        assign rnd_mat[j][i] = rnd[((i*d)-i*(i+1)/2)+(j-1-i)];
        assign rnd_mat[i][j] = rnd_mat[j][i];
        assign rnd_mat_prev[j][i] = rnd_prev[((i*d)-i*(i+1)/2)+(j-1-i)];
        assign rnd_mat_prev[i][j] = rnd_mat_prev[j][i];
    end
end

(* syn_keep = "true", keep = "true" *) wire [d-1:0] not_ina = ~ina;
(* syn_preserve = "true", preserve = "true" *) reg [d-1:0] inb_prev;
always @(posedge clk) inb_prev <= inb;

for(i=0; i<d; i=i+1) begin: ParProdI
    (* syn_preserve = "true", preserve = "true" *) reg [d-2:0] u, v, w;
    (* syn_preserve = "true", preserve = "true" *) reg aibi;
    (* syn_keep = "true", keep = "true" *) wire aibi_comb = ina[i] & inb_prev[i];
    always @(posedge clk) aibi <= aibi_comb;
    assign out[i] = aibi ^ ^u ^ ^w;
    for(j=0; j<d; j=j+1) begin: ParProdJ
        if (i != j) begin: NotEq
            localparam j2 = j < i ?  j : j-1;
            (* syn_keep = "true", keep = "true" *) wire u_j2_comb = not_ina[i] & rnd_mat_prev[i][j];
            (* syn_keep = "true", keep = "true" *) wire v_j2_comb = inb[j] ^ rnd_mat[i][j];
            (* syn_keep = "true", keep = "true" *) wire w_j2_comb = ina[i] & v[j2];
            always @(posedge clk)
            begin
                u[j2] <= u_j2_comb;
                v[j2] <= v_j2_comb;
                w[j2] <= w_j2_comb;
            end
        end
    end
end

endmodule
