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
