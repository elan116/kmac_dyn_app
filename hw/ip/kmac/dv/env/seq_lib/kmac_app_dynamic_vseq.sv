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
