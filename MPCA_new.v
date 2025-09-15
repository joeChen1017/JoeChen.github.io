//==============================================================
// MPCA.v  -  Multi-Packet Channel Arbiter (timing/area tuned)
// Verilog-2001 only. Behavior 1:1 with your logic.
//==============================================================

module _cand_better_(
  input        pick_earliest,         
  input        v_a,  input [2:0] r_a,  input signed [6:0] s_a,  input [2:0] i_a,
  input        v_b,  input [2:0] r_b,  input signed [6:0] s_b,  input [2:0] i_b,
  output       v_o,  output [2:0] r_o, output signed [6:0] s_o, output [2:0] i_o
);
  wire use_b =
    (~v_a &  v_b) ? 1'b1 :
    ( v_a & ~v_b) ? 1'b0 :
    (pick_earliest) ? (
        (r_b < r_a) ? 1'b1 :
        (r_b > r_a) ? 1'b0 :
        (s_b < s_a) ? 1'b1 :
        (s_b > s_a) ? 1'b0 :
        (i_b > i_a)
    ) : (
        (s_b < s_a) ? 1'b1 :
        (s_b > s_a) ? 1'b0 :
        (r_b > r_a) ? 1'b1 :
        (r_b < r_a) ? 1'b0 :
        (i_b > i_a)
    );

  assign v_o = v_a | v_b;
  assign r_o = use_b ? r_b : r_a;
  assign s_o = use_b ? s_b : s_a;
  assign i_o = use_b ? i_b : i_a;
endmodule


// ---- stable compare-swap (same rule: req>score(desc)>idx(asc)) ----
module _cmp_swap_(
  input        req_a, input signed [6:0] sc_a, input [2:0] idx_a,
  input        req_b, input signed [6:0] sc_b, input [2:0] idx_b,
  output [2:0] A_out,  // better
  output [2:0] B_out   // worse
);
  wire swap;
  assign swap =
      (req_b & ~req_a) |
      ((req_a==req_b) & (sc_b > sc_a)) |
      ((req_a==req_b) & (sc_b==sc_a) & (idx_b < idx_a));
  assign A_out = swap ? idx_b : idx_a;
  assign B_out = swap ? idx_a : idx_b;
endmodule

module MPCA(
  input  [127:0] packets,           // {pkt7..pkt0}, each 16b encrypted
  input   [11:0] channel_load,      // {ch2[11:8], ch1[7:4], ch0[3:0]}
  input    [8:0] channel_capacity,  // {cap2[8:6], cap1[5:3], cap0[2:0]}
  input   [63:0] KEY,
  output  [15:0] grant_channel      // {pkt7..pkt0}, 2 bits per pkt
);

  integer i,j,k,t,u,z,ii,jj,si,m;

  // ---------------- key schedule (Speck32/64, 4 rounds) ----------------
  wire [15:0] k0 = KEY[15:0];
  wire [15:0] l0 = KEY[31:16];
  wire [15:0] l1 = KEY[47:32];
  wire [15:0] l2 = KEY[63:48];

  wire [15:0] K0 = k0;
  wire [15:0] K1 = ({K0[6:0], K0[15:7]} + l0) ^ 16'h0000;
  wire [15:0] K2 = ({K1[6:0], K1[15:7]} + l1) ^ 16'h0001;
  wire [15:0] K3 = ({K2[6:0], K2[15:7]} + l2) ^ 16'h0002;

  // ---------------- decrypt 4 blocks -> 8 plain packets ----------------
  // helpers: ROR2(x) = {x[1:0], x[15:2]}, ROL7(x) = {x[8:0], x[15:9]}

  // block 0
  wire [15:0] y4_0 = packets[31:16];
  wire [15:0] x4_0 = packets[15:0];
  wire [15:0] t40  = (y4_0 ^ x4_0);
  wire [15:0] y3_0 = { t40[1:0], t40[15:2] };

  wire [15:0] a30  = (x4_0 ^ K3);
  wire [15:0] b30  = a30 - y3_0;
  wire [15:0] x3_0 = { b30[8:0], b30[15:9] };

  wire [15:0] t30  = (y3_0 ^ x3_0);
  wire [15:0] y2_0 = { t30[1:0], t30[15:2] };

  wire [15:0] a20  = (x3_0 ^ K2);
  wire [15:0] b20  = a20 - y2_0;
  wire [15:0] x2_0 = { b20[8:0], b20[15:9] };

  wire [15:0] t20  = (y2_0 ^ x2_0);
  wire [15:0] y1_0 = { t20[1:0], t20[15:2] };

  wire [15:0] a10  = (x2_0 ^ K1);
  wire [15:0] b10  = a10 - y1_0;
  wire [15:0] x1_0 = { b10[8:0], b10[15:9] };

  wire [15:0] t10  = (y1_0 ^ x1_0);
  wire [15:0] y0_0 = { t10[1:0], t10[15:2] };

  wire [15:0] a00  = (x1_0 ^ K0);
  wire [15:0] b00  = a00 - y0_0;
  wire [15:0] x0_0 = { b00[8:0], b00[15:9] };
  wire [31:0] pblk0 = {y0_0, x0_0};

  // block 1
  wire [15:0] y4_1 = packets[63:48];
  wire [15:0] x4_1 = packets[47:32];
  wire [15:0] t41  = (y4_1 ^ x4_1);
  wire [15:0] y3_1 = { t41[1:0], t41[15:2] };

  wire [15:0] a31  = (x4_1 ^ K3);
  wire [15:0] b31  = a31 - y3_1;
  wire [15:0] x3_1 = { b31[8:0], b31[15:9] };

  wire [15:0] t31  = (y3_1 ^ x3_1);
  wire [15:0] y2_1 = { t31[1:0], t31[15:2] };

  wire [15:0] a21  = (x3_1 ^ K2);
  wire [15:0] b21  = a21 - y2_1;
  wire [15:0] x2_1 = { b21[8:0], b21[15:9] };

  wire [15:0] t21  = (y2_1 ^ x2_1);
  wire [15:0] y1_1 = { t21[1:0], t21[15:2] };

  wire [15:0] a11  = (x2_1 ^ K1);
  wire [15:0] b11  = a11 - y1_1;
  wire [15:0] x1_1 = { b11[8:0], b11[15:9] };

  wire [15:0] t11  = (y1_1 ^ x1_1);
  wire [15:0] y0_1 = { t11[1:0], t11[15:2] };

  wire [15:0] a01  = (x1_1 ^ K0);
  wire [15:0] b01  = a01 - y0_1;
  wire [15:0] x0_1 = { b01[8:0], b01[15:9] };
  wire [31:0] pblk1 = {y0_1, x0_1};

  // block 2
  wire [15:0] y4_2 = packets[95:80];
  wire [15:0] x4_2 = packets[79:64];
  wire [15:0] t42  = (y4_2 ^ x4_2);
  wire [15:0] y3_2 = { t42[1:0], t42[15:2] };

  wire [15:0] a32  = (x4_2 ^ K3);
  wire [15:0] b32  = a32 - y3_2;
  wire [15:0] x3_2 = { b32[8:0], b32[15:9] };

  wire [15:0] t32  = (y3_2 ^ x3_2);
  wire [15:0] y2_2 = { t32[1:0], t32[15:2] };

  wire [15:0] a22  = (x3_2 ^ K2);
  wire [15:0] b22  = a22 - y2_2;
  wire [15:0] x2_2 = { b22[8:0], b22[15:9] };

  wire [15:0] t22  = (y2_2 ^ x2_2);
  wire [15:0] y1_2 = { t22[1:0], t22[15:2] };

  wire [15:0] a12  = (x2_2 ^ K1);
  wire [15:0] b12  = a12 - y1_2;
  wire [15:0] x1_2 = { b12[8:0], b12[15:9] };

  wire [15:0] t12  = (y1_2 ^ x1_2);
  wire [15:0] y0_2 = { t12[1:0], t12[15:2] };

  wire [15:0] a02  = (x1_2 ^ K0);
  wire [15:0] b02  = a02 - y0_2;
  wire [15:0] x0_2 = { b02[8:0], b02[15:9] };
  wire [31:0] pblk2 = {y0_2, x0_2};

  // block 3
  wire [15:0] y4_3 = packets[127:112];
  wire [15:0] x4_3 = packets[111:96];
  wire [15:0] t43  = (y4_3 ^ x4_3);
  wire [15:0] y3_3 = { t43[1:0], t43[15:2] };

  wire [15:0] a33  = (x4_3 ^ K3);
  wire [15:0] b33  = a33 - y3_3;
  wire [15:0] x3_3 = { b33[8:0], b33[15:9] };

  wire [15:0] t33  = (y3_3 ^ x3_3);
  wire [15:0] y2_3 = { t33[1:0], t33[15:2] };

  wire [15:0] a23  = (x3_3 ^ K2);
  wire [15:0] b23  = a23 - y2_3;
  wire [15:0] x2_3 = { b23[8:0], b23[15:9] };

  wire [15:0] t23  = (y2_3 ^ x2_3);
  wire [15:0] y1_3 = { t23[1:0], t23[15:2] };

  wire [15:0] a13  = (x2_3 ^ K1);
  wire [15:0] b13  = a13 - y1_3;
  wire [15:0] x1_3 = { b13[8:0], b13[15:9] };

  wire [15:0] t13  = (y1_3 ^ x1_3);
  wire [15:0] y0_3 = { t13[1:0], t13[15:2] };

  wire [15:0] a03  = (x1_3 ^ K0);
  wire [15:0] b03  = a03 - y0_3;
  wire [15:0] x0_3 = { b03[8:0], b03[15:9] };
  wire [31:0] pblk3 = {y0_3, x0_3};

  // plain packets
  wire [15:0] pkt [0:7];
  assign pkt[0]=pblk0[15:0];   assign pkt[1]=pblk0[31:16];
  assign pkt[2]=pblk1[15:0];   assign pkt[3]=pblk1[31:16];
  assign pkt[4]=pblk2[15:0];   assign pkt[5]=pblk2[31:16];
  assign pkt[6]=pblk3[15:0];   assign pkt[7]=pblk3[31:16];

  // ---------------- channel fields ----------------
  wire [3:0] load_ch [0:2];
  wire [2:0] cap_ch  [0:2];
  assign load_ch[0]=channel_load[3:0];
  assign load_ch[1]=channel_load[7:4];
  assign load_ch[2]=channel_load[11:8];
  assign cap_ch[0]=channel_capacity[2:0];
  assign cap_ch[1]=channel_capacity[5:3];
  assign cap_ch[2]=channel_capacity[8:6];

  // ---------------- field decode ----------------
  wire       req [0:7];
  wire [1:0] qos [0:7], cong [0:7], pref [0:7];
  wire [3:0] len [0:7];
  wire [2:0] src [0:7];
  wire       mode[0:7];
  genvar gi;
  generate
    for (gi=0; gi<8; gi=gi+1) begin: DEC
      assign req [gi] = pkt[gi][15];
      assign qos [gi] = pkt[gi][14:13];
      assign len [gi] = pkt[gi][12:9];
      assign cong[gi] = pkt[gi][8:7];
      assign pref[gi] = pkt[gi][6:5];
      assign src [gi] = pkt[gi][4:2];
      assign mode[gi] = pkt[gi][1];
    end
  endgenerate

  // ---------------- priority score (7-bit signed) ----------------
  reg  signed [6:0] score [0:7];
  reg  signed [6:0] qv, lv, cg, sh, term0, term1, term2, term3;
  reg  signed [7:0] s01, s23;
  always @* begin
    for (si=0; si<8; si=si+1) begin
      if (mode[si]==1'b0) begin
        qv    = {5'b0, qos[si]};
        term0 = (qv - 7'sd2) <<< 2;
        lv    = {3'b0, len[si]};
        term1 = (7'sd8 - lv) <<< 1;
        cg    = {5'b0, cong[si]};
        term2 = ((cg - 7'sd1) <<< 1) + (cg - 7'sd1);
        sh    = {4'b0, src[si]};
        term3 = (sh - 7'sd4);
      end else begin
        qv    = {{5{qos[si][1]}}, qos[si]};
        term0 = (qv - 7'sd2) <<< 2;
        lv    = {{3{len[si][3]}}, len[si]};
        term1 = (7'sd8 - lv) <<< 1;
        cg    = {{5{cong[si][1]}}, cong[si]};
        term2 = ((cg + 7'sd2) <<< 1) + (cg + 7'sd2);
        sh    = {{4{src[si][2]}}, src[si]};
        term3 = (sh - 7'sd4);
      end
      s01 = term0 + term1;
      s23 = term2 + term3;
      score[si] = s01 + s23;
    end
  end

  // ---------------- sorting network -> order[0..7] ----------------
  wire [2:0] s0_0=3'd0,s0_1=3'd1,s0_2=3'd2,s0_3=3'd3,s0_4=3'd4,s0_5=3'd5,s0_6=3'd6,s0_7=3'd7;
  wire [2:0] s1_0,s1_1,s1_2,s1_3,s1_4,s1_5,s1_6,s1_7;
  _cmp_swap_ C10(req[s0_0],score[s0_0],s0_0, req[s0_1],score[s0_1],s0_1, s1_0,s1_1);
  _cmp_swap_ C11(req[s0_2],score[s0_2],s0_2, req[s0_3],score[s0_3],s0_3, s1_2,s1_3);
  _cmp_swap_ C12(req[s0_4],score[s0_4],s0_4, req[s0_5],score[s0_5],s0_5, s1_4,s1_5);
  _cmp_swap_ C13(req[s0_6],score[s0_6],s0_6, req[s0_7],score[s0_7],s0_7, s1_6,s1_7);

  wire [2:0] s2_0,s2_1,s2_2,s2_3,s2_4,s2_5,s2_6,s2_7;
  _cmp_swap_ C20(req[s1_0],score[s1_0],s1_0, req[s1_2],score[s1_2],s1_2, s2_0,s2_2);
  _cmp_swap_ C21(req[s1_1],score[s1_1],s1_1, req[s1_3],score[s1_3],s1_3, s2_1,s2_3);
  _cmp_swap_ C22(req[s1_4],score[s1_4],s1_4, req[s1_6],score[s1_6],s1_6, s2_4,s2_6);
  _cmp_swap_ C23(req[s1_5],score[s1_5],s1_5, req[s1_7],score[s1_7],s1_7, s2_5,s2_7);

  wire [2:0] s3_0,s3_1,s3_2,s3_3,s3_4,s3_5,s3_6,s3_7;
  _cmp_swap_ C30(req[s2_1],score[s2_1],s2_1, req[s2_2],score[s2_2],s2_2, s3_1,s3_2);
  _cmp_swap_ C31(req[s2_5],score[s2_5],s2_5, req[s2_6],score[s2_6],s2_6, s3_5,s3_6);
  _cmp_swap_ C32(req[s2_0],score[s2_0],s2_0, req[s2_4],score[s2_4],s2_4, s3_0,s3_4);
  _cmp_swap_ C33(req[s2_3],score[s2_3],s2_3, req[s2_7],score[s2_7],s2_7, s3_3,s3_7);

  wire [2:0] s4_0,s4_1,s4_2,s4_3,s4_4,s4_5,s4_6,s4_7;
  assign s4_0=s3_0; assign s4_3=s3_3; assign s4_4=s3_4; assign s4_7=s3_7;
  _cmp_swap_ C40(req[s3_1],score[s3_1],s3_1, req[s3_5],score[s3_5],s3_5, s4_1,s4_5);
  _cmp_swap_ C41(req[s3_2],score[s3_2],s3_2, req[s3_6],score[s3_6],s3_6, s4_2,s4_6);

  wire [2:0] s5_0,s5_1,s5_2,s5_3,s5_4,s5_5,s5_6,s5_7;
  assign s5_0=s4_0; assign s5_1=s4_1; assign s5_6=s4_6; assign s5_7=s4_7;
  _cmp_swap_ C50(req[s4_2],score[s4_2],s4_2, req[s4_4],score[s4_4],s4_4, s5_2,s5_4);
  _cmp_swap_ C51(req[s4_3],score[s4_3],s4_3, req[s4_5],score[s4_5],s4_5, s5_3,s5_5);

  wire [2:0] s6_0,s6_1,s6_2,s6_3,s6_4,s6_5,s6_6,s6_7;
  assign s6_0=s5_0; assign s6_1=s5_1; assign s6_2=s5_2; assign s6_5=s5_5; assign s6_6=s5_6; assign s6_7=s5_7;
  _cmp_swap_ C60(req[s5_3],score[s5_3],s5_3, req[s5_4],score[s5_4],s5_4, s6_3,s6_4);

  wire [2:0] order [0:7];
  assign order[0]=s6_0; assign order[1]=s6_1; assign order[2]=s6_2; assign order[3]=s6_3;
  assign order[4]=s6_4; assign order[5]=s6_5; assign order[6]=s6_6; assign order[7]=s6_7;

  // ---------------- ordered-view (one-shot flatten) ----------------
 
  `define SEL_REQ(o)   ((o==3'd0)?req[0]  : (o==3'd1)?req[1]  : (o==3'd2)?req[2]  : (o==3'd3)?req[3]  : (o==3'd4)?req[4]  : (o==3'd5)?req[5]  : (o==3'd6)?req[6]  : req[7])
  `define SEL_PREF(o)  ((o==3'd0)?pref[0] : (o==3'd1)?pref[1] : (o==3'd2)?pref[2] : (o==3'd3)?pref[3] : (o==3'd4)?pref[4] : (o==3'd5)?pref[5] : (o==3'd6)?pref[6] : pref[7])

  wire        req_ord  [0:7];
  wire [1:0]  pref_ord [0:7];
  wire [2:0]  idx_ord  [0:7];
  genvar ov;
  generate for (ov=0; ov<8; ov=ov+1) begin: G_OV
    assign idx_ord[ov]  = order[ov];
    assign req_ord[ov]  = `SEL_REQ(order[ov]);
    assign pref_ord[ov] = `SEL_PREF(order[ov]);
  end endgenerate

  // ---------------- round-1 allocation (fallback + dynamic RR) ----------------
  reg [1:0] alloc0      [0:7];
  reg [3:0] used0       [0:2];
  reg [2:0] alloc_rank0 [0:7];
  reg [1:0] first_ch    [0:7];
  reg       mask_fail   [0:7];

  reg [1:0] pivot,gch,try0,try1,try2;
  reg       pivot_init, ok;

  // +1 / +2 mod 3 lookups
  wire [1:0] nxt_of [0:2];  assign nxt_of[0]=2'd1; assign nxt_of[1]=2'd2; assign nxt_of[2]=2'd0;
  wire [1:0] plus2  [0:2];  assign plus2 [0]=2'd2; assign plus2 [1]=2'd0; assign plus2 [2]=2'd1;

  always @* begin
    used0[0]=0; used0[1]=0; used0[2]=0;
    for (z=0; z<8; z=z+1) begin
      alloc0[z]=2'b11; first_ch[z]=2'b11; alloc_rank0[z]=3'd0;
    end
    pivot=2'd0; pivot_init=1'b0;

   
    for (k=0; k<8; k=k+1) begin
      j = idx_ord[k];

      if (!req_ord[k]) begin
        alloc0[j]=2'b11; first_ch[j]=2'b11; alloc_rank0[j]=k[2:0];
      end
     
      else if ( (pref_ord[k]!=2'b11) && (used0[pref_ord[k]] < cap_ch[pref_ord[k]]) ) begin
        alloc0[j]=pref_ord[k]; first_ch[j]=pref_ord[k]; alloc_rank0[j]=k[2:0];
        if (pref_ord[k]==2'd0) used0[0]=used0[0]+1;
        else if (pref_ord[k]==2'd1) used0[1]=used0[1]+1;
        else used0[2]=used0[2]+1;
      end
      else begin
        if (!pivot_init) begin pivot = (pref_ord[k]==2'b11)?2'd0:pref_ord[k]; pivot_init=1'b1; end
        try0=pivot; try1=plus2[pivot]; try2=nxt_of[pivot];

        // one-level priority select
        begin : SEL_GCH
          reg ok0,ok1,ok2;
          ok0 = (used0[try0] < cap_ch[try0]);
          ok1 = (used0[try1] < cap_ch[try1]) && !ok0;
          ok2 = (used0[try2] < cap_ch[try2]) && !ok0 && !ok1;
          ok  = ok0 | ok1 | ok2;
          gch = ok0 ? try0 : ok1 ? try1 : ok2 ? try2 : 2'b11;
        end

        if (ok) begin
          alloc0[j]=gch; first_ch[j]=gch; alloc_rank0[j]=k[2:0];
          if (gch==2'd0) used0[0]=used0[0]+1;
          else if (gch==2'd1) used0[1]=used0[1]+1;
          else used0[2]=used0[2]+1;
          // pivot = (gch + 1) % 3
          pivot = (gch==2'd0)?2'd1 : (gch==2'd1)?2'd2 : 2'd0;
        end else begin
          // pivot = (pivot + 2) % 3
          pivot = (pivot==2'd0)?2'd2 : (pivot==2'd1)?2'd0 : 2'd1;
        end
      end
    end
  end

  // ---------------- mask (same logic, no / or %) ----------------
  reg [3:0] lch, lch_div3;
  reg [4:0] base_sum, tmp_mod;
  reg [3:0] ms, thr;
  always @* begin
    for (m=0; m<8; m=m+1) begin
      mask_fail[m]=1'b0;
      if (req[m] && alloc0[m]!=2'b11) begin
        case (alloc0[m])
          2'd0: lch = load_ch[0];
          2'd1: lch = load_ch[1];
          default: lch = load_ch[2];
        endcase
        base_sum = {2'b00, score[m][2:1], 1'b0} + {3'b000, pref[m]} + {2'b00, (src[m]^3'b011)} + {1'b0, lch};
        tmp_mod  = base_sum; if (tmp_mod>=5'd20) tmp_mod=tmp_mod-5'd20; if (tmp_mod>=5'd10) tmp_mod=tmp_mod-5'd10;
        ms = tmp_mod[3:0];
        case (lch)
          4'd0,4'd1,4'd2   : lch_div3=4'd0;
          4'd3,4'd4,4'd5   : lch_div3=4'd1;
          4'd6,4'd7,4'd8   : lch_div3=4'd2;
          4'd9,4'd10,4'd11 : lch_div3=4'd3;
          4'd12,4'd13,4'd14: lch_div3=4'd4;
          default          : lch_div3=4'd5;
        endcase
        thr = 4'd7 + lch_div3;
        mask_fail[m] = (ms >= thr);
      end
    end
  end

  // ---------------- global rebalance 


  wire [4:0] tot0 = load_ch[0] + used0[0];
  wire [4:0] tot1 = load_ch[1] + used0[1];
  wire [4:0] tot2 = load_ch[2] + used0[2];
  wire [6:0] sum_all = tot0 + tot1 + tot2;
  

  wire [1:0] max01   = (tot1 > tot0) ? 2'd1 : 2'd0;
  wire [4:0] max01_v = (max01==2'd1) ? tot1 : tot0;
  wire [1:0] max_ch  = (tot2 > max01_v) ? 2'd2 : max01;
  
  wire [1:0] min01   = (tot0 <= tot1) ? 2'd0 : 2'd1;
  wire [4:0] min01_v = (min01==2'd0) ? tot0 : tot1;
  wire [1:0] min_ch  = (min01_v <= tot2) ? min01 : 2'd2;
  
  wire [4:0] max_tot = (max_ch==2'd0)?tot0 : (max_ch==2'd1)?tot1 : tot2;
  wire [4:0] min_tot = (min_ch==2'd0)?tot0 : (min_ch==2'd1)?tot1 : tot2;
  
  // cand_cnt¡G#(alloc0==max_ch)
  wire [3:0] cand_cnt =
      ((alloc0[0]==max_ch) + (alloc0[1]==max_ch)) +
      ((alloc0[2]==max_ch) + (alloc0[3]==max_ch)) +
      ((alloc0[4]==max_ch) + (alloc0[5]==max_ch)) +
      ((alloc0[6]==max_ch) + (alloc0[7]==max_ch));
  
 
  wire cond_def      = ({1'b0, max_tot} << 1) >= sum_all;
  wire cond_sp       = (max_ch==2'd0) && (cand_cnt==4'd2) && ((max_tot - min_tot) >= 5'd5);
  wire cond_gentle   = (cand_cnt==4'd1) && ((max_tot - min_tot) >= 5'd2) && !cond_def && !cond_sp;
  wire do_reb        = cond_def | cond_sp | cond_gentle;
  wire pick_earliest = cond_sp & ~cond_def;
  

  wire v0=(alloc0[0]==max_ch), v1=(alloc0[1]==max_ch), v2=(alloc0[2]==max_ch), v3=(alloc0[3]==max_ch);
  wire v4=(alloc0[4]==max_ch), v5=(alloc0[5]==max_ch), v6=(alloc0[6]==max_ch), v7=(alloc0[7]==max_ch);
  
  wire       A_v,B_v,C_v,D_v;
  wire [2:0] A_r,B_r,C_r,D_r;
  wire signed [6:0] A_s,B_s,C_s,D_s;
  wire [2:0] A_i,B_i,C_i,D_i;
  
  _cand_better_ A (pick_earliest, v0, alloc_rank0[0], score[0], 3'd0,
                                 v1, alloc_rank0[1], score[1], 3'd1,
                                 A_v, A_r, A_s, A_i);
  _cand_better_ B (pick_earliest, v2, alloc_rank0[2], score[2], 3'd2,
                                 v3, alloc_rank0[3], score[3], 3'd3,
                                 B_v, B_r, B_s, B_i);
  _cand_better_ C (pick_earliest, v4, alloc_rank0[4], score[4], 3'd4,
                                 v5, alloc_rank0[5], score[5], 3'd5,
                                 C_v, C_r, C_s, C_i);
  _cand_better_ D (pick_earliest, v6, alloc_rank0[6], score[6], 3'd6,
                                 v7, alloc_rank0[7], score[7], 3'd7,
                                 D_v, D_r, D_s, D_i);
  
  wire       E_v,F_v;
  wire [2:0] E_r,F_r;
  wire signed [6:0] E_s,F_s;
  wire [2:0] E_i,F_i;
  
  _cand_better_ E (pick_earliest, A_v, A_r, A_s, A_i,
                                 B_v, B_r, B_s, B_i,
                                 E_v, E_r, E_s, E_i);
  _cand_better_ F (pick_earliest, C_v, C_r, C_s, C_i,
                                 D_v, D_r, D_s, D_i,
                                 F_v, F_r, F_s, F_i);
  

  wire use_F_when_E = 
    (F_v && (!E_v ||
     ( pick_earliest && ( (F_r < E_r) ||
                          ((F_r==E_r)&&(F_s < E_s)) ||
                          ((F_r==E_r)&&(F_s==E_s)&&(F_i > E_i)) ) ) ||
     (!pick_earliest && ( (F_s < E_s) ||
                          ((F_s==E_s)&&(F_r > E_r)) ||
                          ((F_s==E_s)&&(F_r==E_r)&&(F_i > E_i)) ) )));
  
  wire       found_any = E_v | F_v;
  wire [2:0] best_rank = use_F_when_E ? F_r : E_r;
  wire signed [6:0] best_sc = use_F_when_E ? F_s : E_s;
  wire [2:0] best_idx = use_F_when_E ? F_i : E_i;
  

  wire [1:0] alt1 = (max_ch==2'd0)?2'd1 : (max_ch==2'd1)?2'd2 : 2'd0;
  wire [1:0] alt2 = (max_ch==2'd0)?2'd2 : (max_ch==2'd1)?2'd0 : 2'd1;
  
  wire can1 = (used0[alt1] < cap_ch[alt1]) &&
              ((load_ch[alt1] + used0[alt1] + 1) < 5'd16);
  wire can2 = (used0[alt2] < cap_ch[alt2]) &&
              ((load_ch[alt2] + used0[alt2] + 1) < 5'd16);
  
  wire moved = do_reb & found_any & (can1 | can2);
  wire [1:0] new_ch = can1 ? alt1 : (can2 ? alt2 : 2'b11);
  

  wire [1:0] final0 = (moved && (best_idx==3'd0)) ? new_ch : alloc0[0];
  wire [1:0] final1 = (moved && (best_idx==3'd1)) ? new_ch : alloc0[1];
  wire [1:0] final2 = (moved && (best_idx==3'd2)) ? new_ch : alloc0[2];
  wire [1:0] final3 = (moved && (best_idx==3'd3)) ? new_ch : alloc0[3];
  wire [1:0] final4 = (moved && (best_idx==3'd4)) ? new_ch : alloc0[4];
  wire [1:0] final5 = (moved && (best_idx==3'd5)) ? new_ch : alloc0[5];
  wire [1:0] final6 = (moved && (best_idx==3'd6)) ? new_ch : alloc0[6];
  wire [1:0] final7 = (moved && (best_idx==3'd7)) ? new_ch : alloc0[7];
  
  // ---------------- output ----------------
  assign grant_channel = { final7, final6, final5, final4, final3, final2, final1, final0 };

endmodule
