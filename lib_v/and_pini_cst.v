(* psim_prop = "PINI", psim_strat = "assumed", psim_order=d *)
module and_pini_cst #(parameter d=2) (ina, inb, rnd, clk, out);

	`include "and_pini_cst.inc"

	(* psim_type = "sharing", psim_latency = 3 *) input  [d-1:0] ina;
	(* psim_type = "sharing", psim_latency = 2 *) input  [d-1:0] inb;
	(* psim_type = "sharing", psim_latency = 4 *) output [d-1:0] out;
	(* psim_type = "clock" *) input clk;
        (* psim_type = "random", psim_count=1, psim_rnd_lat_0=0, psim_rnd_count_0=and_pini_nrnd *)
        input [and_pini_nrnd-1:0] rnd;

	wire [d-1:0] inb_ref;

	wire [ref_n_rnd-1:0] rnd_ref;
	assign rnd_ref = rnd[ref_n_rnd-1:0];

	wire [and_pini_mul_nrnd-1:0] rnd_mul, rnd_mul_delayed;
	assign rnd_mul = rnd[and_pini_nrnd-1:ref_n_rnd];

	genvar i;
	for (i=0; i<=2; i=i+1) begin: delay_mat_rnd
		reg [and_pini_mul_nrnd-1:0] mat_rnd;
		if (i==0) begin
			always @(posedge clk)
				mat_rnd <= rnd_mul;
		end else begin
			always @(posedge clk)
				mat_rnd <= delay_mat_rnd[i-1].mat_rnd;
		end
	end
	assign rnd_mul_delayed = delay_mat_rnd[2].mat_rnd;

	MSKref_cst #(.d(d)) rfrsh (.in(inb), .clk(clk), .out(inb_ref), .rnd(rnd_ref));
	MSKand #(.d(d)) mul (.ina(ina), .inb(inb_ref), .clk(clk), .rnd(rnd_mul_delayed), .out(out));

endmodule
