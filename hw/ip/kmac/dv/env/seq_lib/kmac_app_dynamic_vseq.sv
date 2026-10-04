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
    // The inherited sideload-test constraint is disabled in kmac_app_vseq.pre_start(), but
    // test sequences are randomized before pre_start() runs. Disable it here so each dynamic
    // test's own constraints can select sideloading only when needed (e.g. dynamic KMAC).
    en_sideload_c.constraint_mode(0);
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
    // Keep the shared AppOtbn hash-mode consistency constraint enabled for KMAC.
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

// DA-007: sweep every partial final-beat strobe across separate dynamic messages.
class kmac_app_dynamic_partial_msg_vseq extends kmac_app_dynamic_vseq;
  `uvm_object_utils(kmac_app_dynamic_partial_msg_vseq)
  `uvm_object_new

  // Set before each inherited smoke transaction to cover every non-zero partial strobe.
  int unsigned partial_bytes = 1;

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
    // Each message has one full beat followed by a 1-7-byte partial final beat.
    msg.size() == (kmac_pkg::MsgWidth / 8) + partial_bytes;
  }

  function void pre_randomize();
    super.pre_randomize();
    dynamic_app_mode_c.constraint_mode(0);
  endfunction

  virtual task pre_start();
    super.pre_start();
    cfg.require_dynamic_partial_msg = 1'b1;
  endtask

  virtual task body();
    for (int unsigned tail_bytes = 1; tail_bytes < kmac_pkg::MsgWidth / 8; tail_bytes++) begin
      partial_bytes = tail_bytes;
      `uvm_info(`gfn, $sformatf("DA-007 dynamic message with %0d-byte final beat", tail_bytes),
                UVM_LOW)
      // num_trans is fixed to one; each call runs and finishes a distinct dynamic session.
      super.body();
    end
  endtask

  virtual task post_start();
    cfg.require_dynamic_partial_msg = 1'b0;
    super.post_start();
  endtask
endclass

// DA-008: send the dynamic session configuration followed by an empty final message beat.
class kmac_app_dynamic_empty_msg_vseq extends kmac_app_dynamic_vseq;
  `uvm_object_utils(kmac_app_dynamic_empty_msg_vseq)
  `uvm_object_new

  constraint num_trans_c {
    num_trans == 1;
  }

  constraint empty_dynamic_msg_c {
    app_mode == AppOtbn;
    en_app == 1'b1;
    kmac_en == 1'b0;
    hash_mode == sha3_pkg::Shake;
    strength == sha3_pkg::L256;
    xof_en == 1'b1;
    output_len == 16;
    msg.size() == 0;
  }

  function void pre_randomize();
    super.pre_randomize();
    dynamic_app_mode_c.constraint_mode(0);
    // The generic app sequence normally forbids zero-length input messages.
    app_msg_size_c.constraint_mode(0);
  endfunction

  virtual task pre_start();
    super.pre_start();
    cfg.require_dynamic_empty_msg = 1'b1;
  endtask

  virtual task post_start();
    cfg.require_dynamic_empty_msg = 1'b0;
    super.post_start();
  endtask
endclass

// DA-009: consume a finite XOF stream spanning multiple complete digest rates, then finish.
class kmac_app_dynamic_xof_stream_vseq extends kmac_app_dynamic_vseq;
  `uvm_object_utils(kmac_app_dynamic_xof_stream_vseq)
  `uvm_object_new

  localparam int unsigned Shake256ResponseBeatsPerRate = 136 / (kmac_pkg::DynAppDigestW / 8);
  localparam int unsigned SelectedXofResponseBeats = 2 * Shake256ResponseBeatsPerRate + 1;

  constraint num_trans_c {
    num_trans == 1;
  }

  constraint dynamic_xof_stream_c {
    app_mode == AppOtbn;
    en_app == 1'b1;
    kmac_en == 1'b0;
    hash_mode == sha3_pkg::Shake;
    strength == sha3_pkg::L256;
    xof_en == 1'b1;
    output_len == 16;
  }

  function void pre_randomize();
    super.pre_randomize();
    dynamic_app_mode_c.constraint_mode(0);
  endfunction

  virtual task pre_start();
    super.pre_start();
    dynamic_xof_response_beats = SelectedXofResponseBeats;
    cfg.require_dynamic_xof_stream = 1'b1;
    cfg.expected_dynamic_xof_response_beats = SelectedXofResponseBeats;
  endtask

  virtual task post_start();
    cfg.require_dynamic_xof_stream = 1'b0;
    cfg.expected_dynamic_xof_response_beats = 0;
    super.post_start();
  endtask
endclass

// DA-012: sweep every invalid dynamic mode/strength/XOF combination through error and finish.
class kmac_app_dynamic_invalid_cfg_vseq extends kmac_app_dynamic_vseq;
  `uvm_object_utils(kmac_app_dynamic_invalid_cfg_vseq)
  `uvm_object_new

  localparam int unsigned NumInvalidDynamicCfgs = 50;

  kmac_pkg::app_mode_e test_mode = kmac_pkg::AppSHA3;
  sha3_pkg::keccak_strength_e test_strength = sha3_pkg::L256;
  bit test_xof = 1'b1;

  constraint num_trans_c {
    num_trans == 1;
  }

  constraint invalid_dynamic_cfg_c {
    app_mode == AppOtbn;
    en_app == 1'b1;
    kmac_en == (test_mode == kmac_pkg::AppKMAC);
    hash_mode == (test_mode == kmac_pkg::AppSHA3 ? sha3_pkg::Sha3 :
                  test_mode == kmac_pkg::AppShake ? sha3_pkg::Shake : sha3_pkg::CShake);
    // Keep software-side init/read operations on a legal strength. The actual dynamic config
    // strength is overridden below so reserved encodings are tested without corrupting setup.
    strength == sha3_pkg::L256;
    xof_en == test_xof;
    reg_en_sideload == (test_mode == kmac_pkg::AppKMAC);
    entropy_ready == 1'b1;
    if (test_mode == kmac_pkg::AppSHA3) output_len == 32;
    else if (test_mode == kmac_pkg::AppKMAC) output_len == kmac_pkg::AppDigestW / 8;
    else output_len == 16;
    msg.size() == 13;
  }

  function void pre_randomize();
    super.pre_randomize();
    dynamic_app_mode_c.constraint_mode(0);
  endfunction

  function automatic bit is_valid_dynamic_cfg(kmac_pkg::app_mode_e mode,
                                               sha3_pkg::keccak_strength_e cfg_strength,
                                               bit cfg_xof);
    bit strength_valid;
    bit xof_valid;

    case (mode)
      kmac_pkg::AppSHA3: begin
        strength_valid = cfg_strength inside {sha3_pkg::L224, sha3_pkg::L256,
                                              sha3_pkg::L384, sha3_pkg::L512};
        xof_valid = !cfg_xof;
      end
      kmac_pkg::AppShake, kmac_pkg::AppCShake: begin
        strength_valid = cfg_strength inside {sha3_pkg::L128, sha3_pkg::L256};
        xof_valid = 1'b1;
      end
      kmac_pkg::AppKMAC: begin
        strength_valid = cfg_strength inside {sha3_pkg::L128, sha3_pkg::L256};
        xof_valid = !cfg_xof;
      end
      default: begin
        strength_valid = 1'b0;
        xof_valid = 1'b0;
      end
    endcase
    return strength_valid && xof_valid;
  endfunction

  virtual task pre_start();
    super.pre_start();
    cfg.require_dynamic_invalid_cfg = 1'b1;
  endtask

  virtual task body();
    int unsigned invalid_cfgs_run = 0;

    // All two-bit mode encodings map to SHA3/SHAKE/cSHAKE/KMAC. The strength field has eight
    // encodings and en_xof is one bit, giving 64 combinations. Fourteen are legal; exercise each
    // of the other 50 exactly once. Each parent body call runs a complete app session.
    for (int unsigned mode_idx = 0; mode_idx < 4; mode_idx++) begin
      for (int unsigned strength_idx = 0; strength_idx < 8; strength_idx++) begin
        for (int unsigned xof_idx = 0; xof_idx < 2; xof_idx++) begin
          test_mode = kmac_pkg::app_mode_e'(mode_idx);
          test_strength = sha3_pkg::keccak_strength_e'(strength_idx);
          test_xof = (xof_idx != 0);

          if (!is_valid_dynamic_cfg(test_mode, test_strength, test_xof)) begin
            cfg.dynamic_invalid_cfg_strength = test_strength;
            `uvm_info(`gfn,
                      $sformatf("DA-012 invalid cfg mode=%0s strength=%0d en_xof=%0b",
                                test_mode.name(), test_strength, test_xof), UVM_LOW)
            super.body();
            invalid_cfgs_run++;
          end
        end
      end
    end

    `DV_CHECK_EQ_FATAL(invalid_cfgs_run, NumInvalidDynamicCfgs)
  endtask

  virtual task post_start();
    cfg.require_dynamic_invalid_cfg = 1'b0;
    cfg.dynamic_invalid_cfg_strength = sha3_pkg::L256;
    super.post_start();
  endtask
endclass

// DA-018: complete all four dynamic modes in a seed-dependent random order without resetting.
class kmac_app_dynamic_mixed_modes_vseq extends kmac_app_dynamic_vseq;
  `uvm_object_utils(kmac_app_dynamic_mixed_modes_vseq)
  `uvm_object_new

  // A legal initial mode is needed for the test's randomization before body() runs.
  // body() assigns this non-random field before each inherited message transaction.
  kmac_pkg::app_mode_e test_mode = kmac_pkg::AppSHA3;

  constraint num_trans_c {
    num_trans == 1;
  }

  constraint mixed_dynamic_modes_c {
    app_mode == AppOtbn;
    en_app == 1'b1;
    kmac_en == (test_mode == kmac_pkg::AppKMAC);
    hash_mode == (test_mode == kmac_pkg::AppSHA3 ? sha3_pkg::Sha3 :
                  test_mode == kmac_pkg::AppShake ? sha3_pkg::Shake : sha3_pkg::CShake);
    xof_en == 1'b0;
    reg_en_sideload == (test_mode == kmac_pkg::AppKMAC);
    entropy_ready == 1'b1;
    if (test_mode == kmac_pkg::AppSHA3) {
      strength inside {sha3_pkg::L224, sha3_pkg::L256, sha3_pkg::L384, sha3_pkg::L512};
      // The base output_len_sha3_c constraint selects the digest length for this strength.
    } else {
      strength inside {sha3_pkg::L128, sha3_pkg::L256};
      if (test_mode == kmac_pkg::AppKMAC) output_len == kmac_pkg::AppDigestW / 8;
      else output_len == (strength == sha3_pkg::L128 ? 168 : 136);
    }
    msg.size() inside {[1:64]};
  }

  function void pre_randomize();
    super.pre_randomize();
    dynamic_app_mode_c.constraint_mode(0);
  endfunction

  virtual task body();
    kmac_pkg::app_mode_e modes[$] = '{kmac_pkg::AppSHA3, kmac_pkg::AppShake,
                                     kmac_pkg::AppCShake, kmac_pkg::AppKMAC};

    // Shuffle guarantees every mode runs exactly once; selecting a random mode independently
    // for each session could omit a mode. Different seeds can produce different permutations.
    modes.shuffle();
    foreach (modes[i]) begin
      test_mode = modes[i];
      cfg.require_valid_dynamic_sha3_rsp = (test_mode == kmac_pkg::AppSHA3);
      cfg.require_valid_dynamic_fixed_rsp =
          (test_mode inside {kmac_pkg::AppShake, kmac_pkg::AppCShake});
      cfg.require_valid_dynamic_kmac_rsp = (test_mode == kmac_pkg::AppKMAC);
      `uvm_info(`gfn, $sformatf("DA-018 session %0d/%0d: %0s",
                              i + 1, modes.size(), test_mode.name()), UVM_LOW)
      // Reconfigure CSRs and the sideload key as appropriate, then complete config/message/
      // digest/termination/finish before changing mode. No inter-session reset is requested.
      super.body();
    end
  endtask

  virtual task post_start();
    cfg.require_valid_dynamic_sha3_rsp = 1'b0;
    cfg.require_valid_dynamic_fixed_rsp = 1'b0;
    cfg.require_valid_dynamic_kmac_rsp = 1'b0;
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
