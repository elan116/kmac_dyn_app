// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Directed dynamic-interface sequence using SHAKE with a short XOF stream and explicit
// termination. Static application regressions continue to use kmac_app_vseq unchanged.
class kmac_app_dynamic_vseq extends kmac_app_vseq;
  `uvm_object_utils(kmac_app_dynamic_vseq)
  `uvm_object_new

  constraint dynamic_app_mode_c {
    // Keep this first dynamic regression directed: OTBN, SHAKE, and a known XOF mode exercise the
    // config-first protocol and termination path without adding key/prefix variability.
    app_mode == AppOtbn;
    en_app == 1'b1;
    kmac_en == 1'b0;
    hash_mode == sha3_pkg::Shake;
    strength inside {sha3_pkg::L128, sha3_pkg::L256};
    xof_en == 1'b1;
    output_len == 16;
  }

  function void pre_randomize();
    super.pre_randomize();
    // Disable only the inherited constraints that conflict with this dynamic session: the
    // static-app ID restriction, 64-byte static response size, and base SW-only KMAC XOF rule.
    app_mode_c.constraint_mode(0);
    kmac_app_c.constraint_mode(0);
    xof_en_c.constraint_mode(0);
  endfunction

endclass

// DA-003: fixed-output SHAKE and cSHAKE both return one complete Keccak rate when en_xof=0.
class kmac_app_dynamic_shake_fixed_vseq extends kmac_app_dynamic_vseq;
  `uvm_object_utils(kmac_app_dynamic_shake_fixed_vseq)
  `uvm_object_new

  kmac_pkg::app_mode_e test_mode = kmac_pkg::AppShake;
  sha3_pkg::keccak_strength_e test_strength = sha3_pkg::L128;

  constraint num_trans_c {
    num_trans == 1;
  }

  constraint fixed_xof_mode_c {
    app_mode == AppOtbn;
    en_app == 1'b1;
    kmac_en == 1'b0;
    hash_mode == (test_mode == kmac_pkg::AppShake ? sha3_pkg::Shake : sha3_pkg::CShake);
    strength == test_strength;
    xof_en == 1'b0;
  }

  // Fixed dynamic SHAKE/cSHAKE returns the entire rate in one session: 168 bytes at L128 and
  // 136 bytes at L256. The inherited smoke body uses output_len for its state-window read.
  constraint fixed_output_rate_c {
    output_len == (test_strength == sha3_pkg::L128 ? 168 : 136);
  }

  function void pre_randomize();
    super.pre_randomize();
    // Replace the parent's SHAKE-XOF setup with this class's SHAKE/cSHAKE fixed-output matrix.
    dynamic_app_mode_c.constraint_mode(0);
  endfunction

  virtual task pre_start();
    super.pre_start();
    cfg.require_valid_dynamic_fixed_rsp = 1'b1;
  endtask

  virtual task body();
    kmac_pkg::app_mode_e modes[2] = '{kmac_pkg::AppShake, kmac_pkg::AppCShake};
    sha3_pkg::keccak_strength_e strengths[2] = '{sha3_pkg::L128, sha3_pkg::L256};

    foreach (modes[mode_idx]) begin
      foreach (strengths[strength_idx]) begin
        test_mode = modes[mode_idx];
        test_strength = strengths[strength_idx];
        `uvm_info(`gfn,
                  $sformatf("DA-003 fixed %0s-%0s", test_mode.name(), test_strength.name()),
                  UVM_LOW)
        // The inherited smoke body randomizes one message and runs a complete config/message/
        // response/finish transaction for each mode-strength pair.
        super.body();
      end
    end
  endtask

  virtual task post_start();
    cfg.require_valid_dynamic_fixed_rsp = 1'b0;
    super.post_start();
  endtask
endclass

// DA-004: configure a non-empty cSHAKE customization string through PREFIX CSRs and verify the
// fixed-rate result against the scoreboard's cSHAKE DPI prediction.
class kmac_app_dynamic_cshake_vseq extends kmac_app_dynamic_vseq;
  `uvm_object_utils(kmac_app_dynamic_cshake_vseq)
  `uvm_object_new

  sha3_pkg::keccak_strength_e test_strength = sha3_pkg::L128;

  constraint num_trans_c {
    num_trans == 1;
  }

  constraint cshake_fixed_mode_c {
    app_mode == AppOtbn;
    en_app == 1'b1;
    kmac_en == 1'b0;
    hash_mode == sha3_pkg::CShake;
    strength == test_strength;
    xof_en == 1'b0;
    output_len == (test_strength == sha3_pkg::L128 ? 168 : 136);
  }

  // Exercise prefix serialization and decoding with a deterministic, non-empty customization.
  // The inherited prefix-length constraint sizes the array to match this byte count.
  constraint cshake_customization_c {
    custom_str_len == 8;
    custom_str_arr[0] == 8'd68; // D
    custom_str_arr[1] == 8'd65; // A
    custom_str_arr[2] == 8'd70; // F
    custom_str_arr[3] == 8'd79; // O
    custom_str_arr[4] == 8'd85; // U
    custom_str_arr[5] == 8'd82; // R
    custom_str_arr[6] == 8'd67; // C
    custom_str_arr[7] == 8'd83; // S
  }

  function void pre_randomize();
    super.pre_randomize();
    // Replace the parent's SHAKE-XOF mode and the smoke sequence's empty customization string.
    dynamic_app_mode_c.constraint_mode(0);
    custom_str_len_c.constraint_mode(0);
  endfunction

  virtual task pre_start();
    super.pre_start();
    cfg.require_valid_dynamic_fixed_rsp = 1'b1;
  endtask

  virtual task body();
    sha3_pkg::keccak_strength_e strengths[2] = '{sha3_pkg::L128, sha3_pkg::L256};

    foreach (strengths[i]) begin
      test_strength = strengths[i];
      `uvm_info(`gfn, $sformatf("DA-004 dynamic cSHAKE-%0s, customization=DAFOURCS",
                                test_strength.name()), UVM_LOW)
      // The inherited smoke body randomizes and writes PREFIX before sending the OTBN request.
      super.body();
    end
  endtask

  virtual task post_start();
    cfg.require_valid_dynamic_fixed_rsp = 1'b0;
    super.post_start();
  endtask
endclass

// DA-005: exercise dynamic KMAC using the OTBN sideload key and the compile-time KMAC prefix.
class kmac_app_dynamic_kmac_vseq extends kmac_app_dynamic_vseq;
  `uvm_object_utils(kmac_app_dynamic_kmac_vseq)
  `uvm_object_new

  constraint num_trans_c {
    num_trans == 1;
  }

  constraint dynamic_kmac_mode_c {
    app_mode == AppOtbn;
    en_app == 1'b1;
    kmac_en == 1'b1;
    hash_mode == sha3_pkg::CShake;
    strength == sha3_pkg::L256;
    xof_en == 1'b0;
    output_len == kmac_pkg::AppDigestW / 8;
    reg_en_sideload == 1'b1;
    entropy_ready == 1'b1;
  }

  function void pre_randomize();
    super.pre_randomize();
    // Replace the parent's SHAKE-XOF configuration with dynamic KMAC's fixed-length settings.
    // The shared hash_mode_c constraint contains an AppOtbn-specific branch permitting KMAC, so
    // keep it enabled to retain the common mode consistency checks.
    dynamic_app_mode_c.constraint_mode(0);
  endfunction

  virtual task pre_start();
    super.pre_start();
    cfg.require_valid_dynamic_kmac_rsp = 1'b1;
  endtask

  virtual task post_start();
    cfg.require_valid_dynamic_kmac_rsp = 1'b0;
    super.post_start();
  endtask
endclass

// DA-007: send one complete request beat followed by a partial final message beat.
class kmac_app_dynamic_partial_msg_vseq extends kmac_app_dynamic_vseq;
  `uvm_object_utils(kmac_app_dynamic_partial_msg_vseq)
  `uvm_object_new

  constraint num_trans_c {
    num_trans == 1;
  }

  constraint partial_dynamic_msg_c {
    app_mode == AppOtbn;
    en_app == 1'b1;
    kmac_en == 1'b0;
    hash_mode == sha3_pkg::Shake;
    strength == sha3_pkg::L256;
    xof_en == 1'b1;
    output_len == 16;
    // MsgWidth is 64 bits / 8 bytes: 13 bytes creates one full beat and a 5-byte final beat.
    msg.size() == (kmac_pkg::MsgWidth / 8) + 5;
  }

  function void pre_randomize();
    super.pre_randomize();
    dynamic_app_mode_c.constraint_mode(0);
  endfunction

  virtual task pre_start();
    super.pre_start();
    cfg.require_dynamic_partial_msg = 1'b1;
  endtask

  virtual task post_start();
    cfg.require_dynamic_partial_msg = 1'b0;
    super.post_start();
  endtask
endclass

// DA-002: run a complete OTBN session for each supported SHA3 strength. A single randomized
// strength per test seed would not guarantee coverage of all four SHA3 configurations; iterate
// deliberately while keeping the existing SHAKE/XOF smoke test unchanged.
class kmac_app_dynamic_sha3_vseq extends kmac_app_dynamic_vseq;
  `uvm_object_utils(kmac_app_dynamic_sha3_vseq)
  `uvm_object_new

  // The virtual sequence can be randomized before body() starts. Start with a legal SHA3 strength
  // so that this first randomization succeeds, then select each strength before the inherited
  // smoke body randomizes its next message/configuration pair.
  sha3_pkg::keccak_strength_e test_strength = sha3_pkg::L224;

  // Override the inherited smoke transaction-count constraint rather than adding a conflicting
  // constraint. One call to super.body() should produce exactly one complete dynamic session.
  constraint num_trans_c {
    num_trans == 1;
  }

  // Unlike the SHAKE/XOF parent, SHA3 has a fixed digest size and cannot request another squeeze.
  // The inherited base sequence still ties output_len to the selected SHA3 strength.
  constraint sha3_mode_c {
    app_mode == AppOtbn;
    en_app == 1'b1;
    kmac_en == 1'b0;
    hash_mode == sha3_pkg::Sha3;
    strength == test_strength;
    xof_en == 1'b0;
  }

  function void pre_randomize();
    super.pre_randomize();
    // Remove only the parent's SHAKE/XOF-only constraint. Leaving it active alongside sha3_mode_c
    // would demand both SHA3 and SHAKE (and both xof_en=0 and xof_en=1), so randomization fails.
    // super.pre_randomize() has already disabled the separate static-app-only constraints.
    dynamic_app_mode_c.constraint_mode(0);
  endfunction

  virtual task pre_start();
    super.pre_start();
    cfg.require_valid_dynamic_sha3_rsp = 1'b1;
  endtask

  virtual task body();
    sha3_pkg::keccak_strength_e strengths[4] = '{sha3_pkg::L224, sha3_pkg::L256,
                                                   sha3_pkg::L384, sha3_pkg::L512};

    foreach (strengths[i]) begin
      // This field is non-random: the subsequent randomize(this) in super.body() must preserve the
      // chosen strength while still varying message bytes and other permitted test settings.
      test_strength = strengths[i];
      `uvm_info(`gfn, $sformatf("DA-002 dynamic SHA3 strength %0s", test_strength.name()),
                UVM_LOW)
      // The inherited smoke body configures KMAC, sends one OTBN config-first message session and
      // waits for the dynamic host sequence to drain digest beats through rsp_finish.
      super.body();
    end
  endtask

  virtual task post_start();
    cfg.require_valid_dynamic_sha3_rsp = 1'b0;
    super.post_start();
  endtask
endclass
