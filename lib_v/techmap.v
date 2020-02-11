/*
 *  yosys -- Yosys Open SYnthesis Suite
 *
 *  Copyright (C) 2012  Clifford Wolf <clifford@clifford.at>
 *
 *  Permission to use, copy, modify, and/or distribute this software for any
 *  purpose with or without fee is hereby granted, provided that the above
 *  copyright notice and this permission notice appear in all copies.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ---
 *
 *  The internal logic cell technology mapper.
 *
 * ---
 *
 * fullverif modifications (c) UCLouvain 2019:
 * - we keep only the shift(x) mapping to muxes out of this library.
 * 
 * For fullverif internal usage.
 *
 */

`define MIN(_a, _b) ((_a) < (_b) ? (_a) : (_b))
`define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))



(* techmap_celltype = "$shift $shiftx" *)
module _90_shift_shiftx (A, B, Y);
	parameter A_SIGNED = 0;
	parameter B_SIGNED = 0;
	parameter A_WIDTH = 1;
	parameter B_WIDTH = 1;
	parameter Y_WIDTH = 1;

	input [A_WIDTH-1:0] A;
	input [B_WIDTH-1:0] B;
	output [Y_WIDTH-1:0] Y;

	localparam BB_WIDTH = `MIN($clog2(`MAX(A_WIDTH, Y_WIDTH)) + (B_SIGNED ? 2 : 1), B_WIDTH);
	localparam WIDTH = `MAX(A_WIDTH, Y_WIDTH) + (B_SIGNED ? 2**(BB_WIDTH-1) : 0);

	parameter _TECHMAP_CELLTYPE_ = "";
	localparam extbit = _TECHMAP_CELLTYPE_ == "$shift" ? 1'b0 : 1'bx;

	wire [1023:0] _TECHMAP_DO_00_ = "proc;;";
	wire [1023:0] _TECHMAP_DO_01_ = "CONSTMAP; opt_muxtree; opt_expr -mux_undef -mux_bool -fine;;;";

	integer i;
	reg [WIDTH-1:0] buffer;
	reg overflow;

	always @* begin
		overflow = 0;
		buffer = {WIDTH{extbit}};
		buffer[`MAX(A_WIDTH, Y_WIDTH)-1:0] = A;

		if (B_WIDTH > BB_WIDTH) begin
			if (B_SIGNED) begin
				for (i = BB_WIDTH; i < B_WIDTH; i = i+1)
					if (B[i] != B[BB_WIDTH-1])
						overflow = 1;
			end else
				overflow = |B[B_WIDTH-1:BB_WIDTH];
			if (overflow)
				buffer = {WIDTH{extbit}};
		end

		for (i = BB_WIDTH-1; i >= 0; i = i-1)
			if (B[i]) begin
				if (B_SIGNED && i == BB_WIDTH-1)
					buffer = {buffer, {2**i{extbit}}};
				else if (2**i < WIDTH)
					buffer = {{2**i{extbit}}, buffer[WIDTH-1 : 2**i]};
				else
					buffer = {WIDTH{extbit}};
			end
	end

	assign Y = buffer;
endmodule

