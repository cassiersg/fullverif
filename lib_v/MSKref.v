// SNI refresh gadget, for d=2,...,16
(* fv_prop = "SNI", fv_strat = "assumed", fv_order=d *)
module MSKref #(parameter d=2) (in, clk, out, rnd);

`include "MSKref.vh"

(* syn_keep="true", keep="true", fv_type="sharing", fv_latency=2 *) input [d-1:0] in;
(* syn_keep="true", keep="true", fv_type="sharing", fv_latency=3 *) output reg [d-1:0] out;
(* fv_type="clock" *) input clk;
(* syn_keep="true", keep="true", fv_type= "random", fv_count=1, fv_rnd_lat_0 = 0, fv_rnd_count_0 = ref_n_rnd *)
input [ref_n_rnd-1:0] rnd;

(* syn_preserve = "true", preserve = "true" *) reg [d-1:0] share0;
always @(posedge clk)
    out <= in ^ share0;

if (d == 2) begin
    (* syn_preserve = "true", preserve = "true" *) reg [d-1:0] share0b;
    always @(posedge clk) begin
        share0b <= {rnd[0], rnd[0]};
        share0 <= share0b;
    end
end else if (d==3) begin
    (* syn_preserve = "true", preserve = "true" *) reg [d-1:0] share0b;
    always @(posedge clk) begin
        share0b <= {rnd[0]^rnd[1], rnd[1], rnd[0]};
        share0 <= share0b;
    end
end else if (d==4 || d==5) begin
    wire [d-1:0] r1 = rnd[d-1:0];
    (* syn_preserve = "true", preserve = "true" *) reg [d-1:0] share0b;
    always @(posedge clk) begin
        share0b <= r1[d-1:0] ^ { r1[d-2:0], r1[d-1] };
        share0 <= share0b;
    end
end else if (d <= 12) begin
    wire [d-1:0] r1 = rnd[d-1:0];
    (* syn_preserve = "true", preserve = "true" *) reg [ref_n_rnd-d-1:0] r2;
    always @(posedge clk) r2 <= rnd[ref_n_rnd-1:d];
    (* syn_preserve = "true", preserve = "true" *) reg [d-1:0] s1;
    always @(posedge clk)
        s1 <= r1[d-1:0] ^ { r1[d-2:0], r1[d-1] };
    case (d)
        6: always @(posedge clk)
            share0 <= {s1[d-1:4], s1[3]^r2[0], s1[2:1], s1[0]^r2[0]};
        7: always @(posedge clk)
        share0 <= {
            s1[6]^r2[0],
            s1[5],
            s1[4]^r2[1],
            s1[3],
            s1[2]^r2[0],
            s1[1],
            s1[0]^r2[1]
        };
        8: always @(posedge clk)
        share0 <= {
            s1[7],
            s1[6]^r2[0],
            s1[5]^r2[1],
            s1[4]^r2[2],
            s1[3],
            s1[2]^r2[0],
            s1[1]^r2[1],
            s1[0]^r2[2]
        };
        9: always @(posedge clk)
        share0 <= {
            s1[8],
            s1[7]^r2[0],
            s1[6]^r2[1],
            s1[5],
            s1[4]^r2[2],
            s1[3]^r2[0],
            s1[2],
            s1[1]^r2[1],
            s1[0]^r2[2]
        };
        10: always @(posedge clk)
        share0 <= {
            s1[9]^r2[4],
            s1[8]^r2[3],
            s1[7]^r2[2],
            s1[6]^r2[1],
            s1[5]^r2[0],
            s1[4]^r2[4],
            s1[3]^r2[3],
            s1[2]^r2[2],
            s1[1]^r2[1],
            s1[0]^r2[0]
        };
        11: always @(posedge clk)
        share0 <= {
            s1[10]^r2[0],
            s1[9]^r2[1],
            s1[8]^r2[2],
            s1[7]^r2[3]^r2[0],
            s1[6]^r2[4],
            s1[5]^r2[5],
            s1[4]^r2[1],
            s1[3]^r2[2],
            s1[2]^r2[3],
            s1[1]^r2[4],
            s1[0]^r2[5]
        };
        12: always @(posedge clk)
        share0 <= {
            s1[11]^r2[2]^r2[0],
            s1[10]^r2[3],
            s1[9]^r2[4],
            s1[8]^r2[5]^r2[0],
            s1[7]^r2[6],
            s1[6]^r2[7],
            s1[5]^r2[2]^r2[1],
            s1[4]^r2[3],
            s1[3]^r2[4],
            s1[2]^r2[5]^r2[1],
            s1[1]^r2[6],
            s1[0]^r2[7]
        };
    endcase
end else if (d <= 16) begin
    wire [d-1:0] r1 = rnd[d-1:0];
    wire [ref_n_rnd-d-1:0] r2 = rnd[ref_n_rnd-1:d];
    (* syn_preserve = "true", preserve = "true" *) reg [d-1:0] s1, s2;
    always @(posedge clk) begin
        s1 <= r1[d-1:0] ^ { r1[d-2:0], r1[d-1] };
        s2 <= r1[d-1:0] ^ { r2[d-4:0], r2[d-1:d-3] };
        share0 <= s1 ^ s2;
    end
end

endmodule
