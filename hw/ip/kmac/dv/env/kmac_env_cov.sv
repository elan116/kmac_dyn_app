// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

/**
 * Covergroups that are dependent on run-time parameters that may be available
 * only in build_phase can be defined here
 * Covergroups may also be wrapped inside helper classes if needed.
 */

// Covers various configuration combinations for the masked version of KMAC.
//
// Declare this outside of `kmac_env_cov` so that we can conditionally instantiate this in the
// build_phase depending on a value in the env_cfg object.

// macro for the common KMAC configuration fields
`define COMMON_CFG_CGS \
    kmac_en:      coverpoint kmac; \
    xof_en:       coverpoint xof; \
    strength:     coverpoint kstrength; \
    mode:         coverpoint kmode; \
    key_len:      coverpoint key; \
    msg_endian:   coverpoint msg_endianness; \
    state_endian: coverpoint state_endianness; \
    sideload:     coverpoint en_sideload;

// creates the cross bins for all XOF functions
`define XOF_CROSS_CG(strength_cg, valid_mode_expr) \
      bins valid = ``valid_mode_expr`` && binsof(``strength_cg``) intersect {sha3_pkg::L128, sha3_pkg::L256}; \
      ignore_bins invalid_mode = !``valid_mode_expr``; \
      ignore_bins invalid_strength = !binsof(``strength_cg``) intersect {sha3_pkg::L128, sha3_pkg::L256};

// creates the cross bins for SHA3 functions
`define SHA3_CROSS_CG(mode_cg, strength_cg) \
    bins valid = binsof(``mode_cg``) intersect {sha3_pkg::Sha3}; \
    ignore_bins invalid_mode = !binsof(``mode_cg``) intersect {sha3_pkg::Sha3}; \
    ignore_bins invalid_strength = binsof(``strength_cg``) intersect {sha3_pkg::L128};

// creates a coverpoint to cover different TLUL access granularities
`define MASK_CP(name, mask) \
    ``name``: coverpoint ``mask`` { \
      bins byte_access        = {'b0001, 'b0010, 'b0100, 'b1000}; \
      bins halfword_access    = {'b0011, 'b0110, 'b1100}; \
      bins triple_byte_access = {'b0111, 'b1110}; \
      bins word_access        = {'b1111}; \
    }

// The six-bit index deliberately retains all three encoded strength bits, including reserved
// values 5..7. Prefix selection is not part of legality: RTL overrides it according to mode.
function automatic bit kmac_dynamic_tuple_legal(bit [5:0] tuple);
  case (kmac_pkg::app_mode_e'(tuple[5:4]))
    kmac_pkg::AppSHA3:
      return !tuple[0] && (tuple[3:1] inside {sha3_pkg::L224, sha3_pkg::L256,
                                             sha3_pkg::L384, sha3_pkg::L512});
    kmac_pkg::AppShake, kmac_pkg::AppCShake:
      return tuple[3:1] inside {sha3_pkg::L128, sha3_pkg::L256};
    kmac_pkg::AppKMAC:
      return !tuple[0] && (tuple[3:1] inside {sha3_pkg::L128, sha3_pkg::L256});
    default: return 0;
  endcase
endfunction

covergroup config_masked_cg with function sample(bit kmac, bit xof,
                                                 sha3_pkg::keccak_strength_e kstrength,
                                                 sha3_pkg::sha3_mode_e kmode,
                                                 kmac_pkg::key_len_e key,
                                                 bit msg_endianness,
                                                 bit state_endianness,
                                                 bit en_sideload,
                                                 kmac_pkg::entropy_mode_e entr_mode,
                                                 bit fast_entropy);
  `COMMON_CFG_CGS

  entropy_mode: coverpoint entr_mode;

  entropy_fast_process: coverpoint fast_entropy;

  // cross the various configuration settings

  kmac_cross: cross kmac_en, xof_en, strength, key_len, msg_endian,
                    state_endian, entropy_mode, entropy_fast_process {
    `XOF_CROSS_CG(strength, binsof(kmac_en) intersect {1})
  }

  cshake_cross: cross mode, strength, msg_endian, state_endian,
                               entropy_mode, entropy_fast_process {
    `XOF_CROSS_CG(strength, binsof(mode) intersect {sha3_pkg::CShake})
  }

  shake_cross: cross mode, strength, msg_endian, state_endian,
                              entropy_mode, entropy_fast_process {
    `XOF_CROSS_CG(strength, binsof(mode) intersect {sha3_pkg::Shake})
  }

  sha3_cross: cross mode, strength, msg_endian, state_endian,
                    entropy_mode, entropy_fast_process {
    `SHA3_CROSS_CG(mode, strength)
  }
endgroup


// Covers various configuration combinations for the unmasked version of KMAC.
//
// Declare this outside of `kmac_env_cov` so that we can conditionally instantiate this in the
// `build_phase` depending on a value in the env_cfg object.
covergroup config_unmasked_cg with function sample(bit kmac, bit xof,
                                                   sha3_pkg::keccak_strength_e kstrength,
                                                   sha3_pkg::sha3_mode_e kmode,
                                                   kmac_pkg::key_len_e key,
                                                   bit msg_endianness,
                                                   bit state_endianness,
                                                   bit en_sideload);
  `COMMON_CFG_CGS

  // cross the various configuration settings

  kmac_cross: cross kmac_en, xof_en, strength, key_len, msg_endian, state_endian {
    `XOF_CROSS_CG(strength, binsof(kmac_en) intersect {1})
  }

  cshake_cross: cross mode, strength, msg_endian, state_endian {
    `XOF_CROSS_CG(strength, binsof(mode) intersect {sha3_pkg::CShake})
  }

  shake_cross: cross mode, strength, msg_endian, state_endian {
    `XOF_CROSS_CG(strength, binsof(mode) intersect {sha3_pkg::Shake})
  }

  sha3_cross: cross mode, strength, msg_endian, state_endian {
    `SHA3_CROSS_CG(mode, strength)
  }

endgroup

// Wrapper class for the covergroup for the application interface.
//
// We do this so that we can create an array of these covergroups for each app interface
// present in the testbench environment.
class app_cg_wrap;
  // done signal is sent while Keccak rounds are running
  covergroup app_cg(string name) with function sample(bit single_beat,
                                                      bit [keymgr_pkg::KmacDataIfWidth/8-1:0] strb,
                                                      bit err,
                                                      bit is_done,
                                                      bit in_keccak,
                                                      bit is_response = 0);
    option.per_instance = 1;
    option.name = name;

    single_data_beat: coverpoint single_beat iff (is_response);

    data_strb: coverpoint strb iff (!is_response) {
      bins zero_bytes     = {'0};
      bins one_byte       = {'b0000_0001};
      bins two_bytes      = {'b0000_0011};
      bins three_bytes    = {'b0000_0111};
      bins four_bytes     = {'b0000_1111};
      bins five_bytes     = {'b0001_1111};
      bins six_bytes      = {'b0011_1111};
      bins seven_bytes    = {'b0111_1111};
      bins full_data_beat = {'1};
      bins invalid        = default;
    }

    app_err: coverpoint err iff (is_response);

    // req_last ends message absorption; an accepted response finishes the session separately.
    done: coverpoint is_done iff (!is_response);
    response_finish: coverpoint is_done iff (is_response);

    in_keccak_rounds: coverpoint in_keccak iff (!is_response);

    partial_data_on_last_beat: cross done, data_strb iff (!is_response) {
      // Retain a separate cross bin for every final-beat strobe, rather than aggregating them.
      ignore_bins invalid = !binsof(done) intersect {1};
    }

    done_in_keccak_rounds: cross done, in_keccak_rounds iff (!is_response) {
      ignore_bins invalid = !binsof(done) intersect {1};
    }
  endgroup

  covergroup app_cfg_reg_cg(string name) with function sample(sha3_pkg::sha3_mode_e sw_hash_mode);
    option.per_instance = 1;
    option.name = name;
    sw_configured_hash_mode: coverpoint sw_hash_mode {
      bins sha3   = {sha3_pkg::Sha3};
      bins shake  = {sha3_pkg::Shake};
      bins cshake = {sha3_pkg::CShake};
    }
  endgroup

  function new(string name = "app_cg");
    app_cg = new(name);
    // Xcelium requires unique explicit names for covergroup instances in this scope.
    app_cfg_reg_cg = new({name, "_cfg_reg"});
  endfunction

  function void app_sample(bit single_beat,
                           bit [keymgr_pkg::KmacDataIfWidth/8-1:0] strb,
                           bit err,
                           bit is_done,
                           bit in_keccak,
                           bit is_response = 0);
    app_cg.sample(single_beat, strb, err, is_done, in_keccak, is_response);
  endfunction

  function void app_cfg_reg_sample(sha3_pkg::sha3_mode_e sw_hash_mode);
    app_cfg_reg_cg.sample(sw_hash_mode);
  endfunction
endclass


class kmac_env_cov extends cip_base_env_cov #(.CFG_T(kmac_env_cfg));
  `uvm_component_utils(kmac_env_cov)

  // the base class provides the following handles for use:
  // kmac_env_cfg: cfg

  // covergroups

  config_masked_cg config_masked_cg;
  config_unmasked_cg config_unmasked_cg;

  app_cg_wrap app_cg_wrappers[kmac_env_pkg::NUM_APP_INTF];

  // Dynamic-interface coverage is split by what the passive monitor/scoreboard observes:
  // requested configs, request framing, completed sessions, response streams, and mode-specific
  // digest/prefix/key behavior. Config and session tuple bins are explicitly named for IMC.
  // DA-010/011/013..017 remain future scope; these groups make no pending-response, stall, reset,
  // or fault-coverage claims.
  // Runtime config coverage: all encoded mode/strength/XOF requests, plus a separate cross for
  // invalid configs that produced an error and were then closed with an accepted finish.
  covergroup dynamic_app_config_cg with function sample(kmac_pkg::app_mode_e mode_value,
                                                        sha3_pkg::keccak_strength_e strength_value,
                                                        bit xof_value,
                                                        bit rejected_finish);
    option.per_instance = 1;
    mode: coverpoint mode_value {
      bins sha3 = {kmac_pkg::AppSHA3};
      bins shake = {kmac_pkg::AppShake};
      bins cshake = {kmac_pkg::AppCShake};
      bins kmac = {kmac_pkg::AppKMAC};
    }
    strength: coverpoint strength_value {
      bins l128 = {sha3_pkg::L128};
      bins l224 = {sha3_pkg::L224};
      bins l256 = {sha3_pkg::L256};
      bins l384 = {sha3_pkg::L384};
      bins l512 = {sha3_pkg::L512};
      bins reserved_5 = {sha3_pkg::keccak_strength_e'(3'b101)};
      bins reserved_6 = {sha3_pkg::keccak_strength_e'(3'b110)};
      bins reserved_7 = {sha3_pkg::keccak_strength_e'(3'b111)};
    }
    xof: coverpoint xof_value {
      bins disabled = {1'b0};
      bins enabled = {1'b1};
    }
    rejected_finish_cp: coverpoint rejected_finish {
      bins config_observed = {1'b0};
      bins error_then_finish = {1'b1};
    }

    // Named axes make IMC's generated cross-bin names readable, e.g. sha3_l224_disabled.
    requested_configurations: cross mode, strength, xof iff (!rejected_finish);

    // Only sample this cross when the scoreboard observed an invalid config's error and finish.
    rejected_configurations_finished: cross mode, strength, xof iff (rejected_finish);
  endgroup

  // Request-level framing coverage. phase is classified by the scoreboard as config, message,
  // or termination; byte-count bins come from the monitor's observed request strobe.
  covergroup dynamic_app_request_cg with function sample(int unsigned phase,
                                                         int unsigned num_bytes,
                                                         bit last);
    option.per_instance = 1;
    request_phase: coverpoint phase {
      bins configuration = {0};
      bins message = {1};
      bins termination = {2};
    }
    message_bytes: coverpoint num_bytes iff (phase == 1) {
      bins empty = {0};
      bins partial[] = {[1:7]};
      bins full = {8};
    }
    message_last: coverpoint last iff (phase == 1) {
      bins continues = {1'b0};
      bins ends_message = {1'b1};
    }
    termination_empty_last: coverpoint (num_bytes == 0 && last) iff (phase == 2) {
      bins empty_last_request = {1'b1};
      bins other_termination = {1'b0};
    }
    message_strobe_last: cross message_bytes, message_last iff (phase == 1);
  endgroup

  // Session-level coverage sampled only at accepted finish. Explicit legal_configuration bin
  // names describe the tuple (e.g. sha3_l224_xof_disabled); framing comes from FIFO-processed
  // phase markers, not assumed ordering between independent request/response consumers.
  covergroup dynamic_app_session_cg with function sample(bit [5:0] tuple,
                                                         int unsigned beats,
                                                         bit empty,
                                                         bit [2:0] framing,
                                                         bit error_seen);
    option.per_instance = 1;
    // Tuple values remain the sampled encoding, but named bins expose mode/strength/XOF directly
    // in IMC. Invalid tuples are excluded because this group tracks completed legal sessions.
    legal_configuration: coverpoint tuple {
      bins sha3_l224_xof_disabled = {6'd2};
      bins sha3_l256_xof_disabled = {6'd4};
      bins sha3_l384_xof_disabled = {6'd6};
      bins sha3_l512_xof_disabled = {6'd8};
      bins shake_l128_xof_disabled = {6'd16};
      bins shake_l128_xof_enabled = {6'd17};
      bins shake_l256_xof_disabled = {6'd20};
      bins shake_l256_xof_enabled = {6'd21};
      bins cshake_l128_xof_disabled = {6'd32};
      bins cshake_l128_xof_enabled = {6'd33};
      bins cshake_l256_xof_disabled = {6'd36};
      bins cshake_l256_xof_enabled = {6'd37};
      bins kmac_l128_xof_disabled = {6'd48};
      bins kmac_l256_xof_disabled = {6'd52};
      ignore_bins invalid_configuration = {[0:1], 3, 5, 7, [9:15], [18:19], [22:31],
                   [34:35], [38:47], [49:51], [53:63]};
    }
    message_beats: coverpoint beats {
      bins none = {0};
      bins single = {1};
      bins two = {2};
      bins multi = {[3:$]};
    }
    empty_message: coverpoint empty {
      bins non_empty = {1'b0};
      bins empty = {1'b1};
    }
    processed_framing: coverpoint framing {
      bins config_message_termination = {3'b111};
      bins missing_config = {3'b011};
      bins missing_message = {3'b101};
      bins missing_termination = {3'b110};
      bins other_incomplete = default;
    }
    outcome: coverpoint error_seen { bins success = {0}; bins error = {1}; }
    config_empty_outcome: cross legal_configuration, empty_message, outcome;
    config_beats_outcome: cross legal_configuration, message_beats, outcome;
    framing_outcome: cross processed_framing, outcome;
  endgroup

  // Completed-session response coverage for SHAKE/cSHAKE. Chunks are accepted non-error,
  // non-finish response beats; rate categories are relative to the selected Keccak rate. Explicit
  // tuple names make IMC crosses readable. No pending or drain count is inferred here.
  covergroup dynamic_app_stream_cg with function sample(bit [5:0] tuple,
                                                        int unsigned chunks,
                                                        int unsigned rate_category,
                                                        bit termination_seen,
                                                        bit error_seen);
    option.per_instance = 1;
    // Only SHAKE/cSHAKE stream tuples are sampled here. Spell out the valid configurations in
    // the bin names so the rate crosses are directly recognizable in IMC.
    stream_configuration: coverpoint tuple {
      bins shake_l128_xof_disabled = {6'd16};
      bins shake_l128_xof_enabled = {6'd17};
      bins shake_l256_xof_disabled = {6'd20};
      bins shake_l256_xof_enabled = {6'd21};
      bins cshake_l128_xof_disabled = {6'd32};
      bins cshake_l128_xof_enabled = {6'd33};
      bins cshake_l256_xof_disabled = {6'd36};
      bins cshake_l256_xof_enabled = {6'd37};
      ignore_bins non_stream_configuration = {[0:15], [18:19], [22:31], [34:35], [38:63]};
    }
    accepted_chunks: coverpoint chunks {
      bins zero = {0}; bins single = {1}; bins multiple = {[2:$]};
    }
    relative_rate: coverpoint rate_category {
      bins zero = {0}; bins below_one_rate = {1}; bins one_rate = {2};
      bins between_one_two_rates = {3}; bins two_rates = {4}; bins above_two_rates = {5};
    }
    processed_termination: coverpoint termination_seen {
      bins termination_observed = {1'b1};
      bins termination_missing = {1'b0};
    }
    outcome: coverpoint error_seen { bins success = {0}; bins error = {1}; }
    rate_outcome: cross stream_configuration, relative_rate, outcome;
    termination_outcome: cross stream_configuration, processed_termination, outcome;
  endgroup

  // SHA3 logical digest size versus observed dynamic transport bytes. SHA3-224 logically has 28
  // bytes but transports four 64-bit beats (32 bytes); mismatched pairs are ignored.
  covergroup dynamic_app_sha3_digest_cg with function sample(int unsigned logical_bytes,
                                                             int unsigned transport_bytes);
    option.per_instance = 1;
    logical_length: coverpoint logical_bytes {
      bins sha3_224 = {28}; bins sha3_256 = {32};
      bins sha3_384 = {48}; bins sha3_512 = {64};
    }
    transport_length: coverpoint transport_bytes {
      bins bytes_32 = {32}; bins bytes_48 = {48}; bins bytes_64 = {64};
    }
    logical_transport: cross logical_length, transport_length {
      ignore_bins mismatched =
          (binsof(logical_length) intersect {28,32} &&
           !binsof(transport_length) intersect {32}) ||
          (binsof(logical_length) intersect {48} &&
           !binsof(transport_length) intersect {48}) ||
          (binsof(logical_length) intersect {64} &&
           !binsof(transport_length) intersect {64});
    }
  endgroup

  // Crosses the modes of consecutive sessions only after each has reached accepted finish.
  covergroup dynamic_app_transition_cg with function sample(kmac_pkg::app_mode_e previous_mode,
                                                            kmac_pkg::app_mode_e current_mode,
                                                            bit previous_error,
                                                            bit current_error);
    option.per_instance = 1;
    previous: coverpoint previous_mode {
      bins previous_sha3 = {kmac_pkg::AppSHA3};
      bins previous_shake = {kmac_pkg::AppShake};
      bins previous_cshake = {kmac_pkg::AppCShake};
      bins previous_kmac = {kmac_pkg::AppKMAC};
    }
    current: coverpoint current_mode {
      bins current_sha3 = {kmac_pkg::AppSHA3};
      bins current_shake = {kmac_pkg::AppShake};
      bins current_cshake = {kmac_pkg::AppCShake};
      bins current_kmac = {kmac_pkg::AppKMAC};
    }
    previous_outcome: coverpoint previous_error {
      bins previous_success = {0}; bins previous_error = {1};
    }
    current_outcome: coverpoint current_error {
      bins current_success = {0}; bins current_error = {1};
    }
    finished_modes: cross previous, current;
    finished_outcomes: cross previous_outcome, current_outcome;
  endgroup

  // Records the effective prefix source and cSHAKE N/S lengths. Only lengths are covered; prefix
  // contents and key material are intentionally not exposed as coverage data.
  covergroup dynamic_app_prefix_cg with function sample(kmac_pkg::app_mode_e mode,
                                                        bit app_prefix,
                                                        int unsigned fname_len,
                                                        int unsigned custom_len,
                                                        bit error_seen);
    option.per_instance = 1;
    // Effective source, not the ignored prefix_mode bit in the configuration request.
    mode_source: coverpoint {mode, app_prefix} {
      bins cshake_csr = {{kmac_pkg::AppCShake, 1'b0}};
      bins kmac_app = {{kmac_pkg::AppKMAC, 1'b1}};
    }
    // KMAC's compile-time N/S are fixed; length coverage targets variable cSHAKE CSR prefixes.
    function_length: coverpoint fname_len iff (mode == kmac_pkg::AppCShake) {
      bins empty = {0}; bins shorter = {[1:sha3_pkg::FnWidth/8-1]};
      bins maximum = {sha3_pkg::FnWidth/8};
    }
    customization_length: coverpoint custom_len iff (mode == kmac_pkg::AppCShake) {
      bins empty = {0}; bins shorter = {[1:sha3_pkg::CsWidth/8-1]};
      bins maximum = {sha3_pkg::CsWidth/8};
    }
    // Prefix decoding is deliberately restricted to non-error completed sessions.
    outcome: coverpoint error_seen {
      bins success = {0};
      ignore_bins error = {1};
    }
    source_outcome: cross mode_source, outcome;
    lengths_outcome: cross function_length, customization_length, outcome
      iff (mode == kmac_pkg::AppCShake);
  endgroup

  // Dynamic KMAC key metadata sampled per completed session: validity snapshot at config, actual
  // sideload source, effective key length, and response outcome. Secret key bits are never sampled.
  covergroup dynamic_app_key_cg with function sample(bit key_valid,
                                                     kmac_pkg::key_len_e effective_length,
                                                     bit actual_sideload,
                                                     bit error_seen);
    option.per_instance = 1;
    validity_at_config: coverpoint key_valid {
      bins valid_key = {1'b1};
      bins invalid_key = {1'b0};
    }
    key_source: coverpoint actual_sideload { bins sideload = {1}; }
    key_length: coverpoint effective_length { bins key256 = {kmac_pkg::Key256}; }
    outcome: coverpoint error_seen { bins success = {0}; bins error = {1}; }
    key_outcome: cross validity_at_config, key_source, key_length, outcome;
  endgroup

  covergroup msg_len_cg with function sample(int len);
    msg_len: coverpoint len {
      bins len_0                    = {0};
      bins len_1                    = {1};
      bins len_keccak_block_sizes[] = {72, 104, 136, 144, 168};
      bins len_0_256                = {[0 : 256]};
      bins len_257_512              = {[257 : 512]};
      bins len_513_768              = {[513 : 768]};
      bins len_769_1024             = {[769 : 1024]};
      bins len_1025_2500            = {[1025 : 2500]};
      bins len_2501_5000            = {[2501 : 5000]};
      bins len_5001_7500            = {[5001 : 7500]};
      bins len_7501_10000           = {[7501 : 10_000]};
      bins remainder                = default;
    }
  endgroup

  covergroup output_digest_len_cg with function sample(int len);
    output_digest_len: coverpoint len {
      bins len_1                            = {1};
      bins len_2_63                         = {[2 : 63]};
      bins len_datapath_width               = {64};
      bins len_keccak_block_sizes[]         = {72, 104, 136, 144, 168};
      bins len_min_for_xof_require_squeeze  = {137, 169};
      bins len_65_200                       = {[65  : 200]};
      bins len_201_400                      = {[201 : 400]};
      bins len_401_600                      = {[401 : 600]};
      bins len_601_800                      = {[601 : 800]};
      bins len_801_1000                     = {[801 : 1_000]};
      bins remainder                        = default;
    }
  endgroup

  covergroup prefix_range_cg with function sample(byte b);
    prefix_range: coverpoint b {
      bins space              = {32};
      bins capital_letters    = {[65 : 90]};
      bins lowercase_letters  = {[97 : 122]};
      bins rest               = default;
    }
  endgroup

  covergroup msgfifo_write_mask_cg with function sample(bit [TL_DBW-1:0] mask);
    `MASK_CP(msgfifo_write_mask, mask)
  endgroup

  covergroup msgfifo_level_cg with function sample(bit fifo_empty, bit fifo_full, bit [4:0] fifo_depth,
                                                   sha3_pkg::sha3_mode_e mode, bit kmac_en);
    kmac_mode: coverpoint kmac_en;
    hash_mode: coverpoint mode {
      bins sha3   = {sha3_pkg::Sha3};
      bins shake  = {sha3_pkg::Shake};
      bins cshake = {sha3_pkg::CShake};
    }
    msgfifo_empty:  coverpoint fifo_empty;
    msgfifo_full:   coverpoint fifo_full;
    msgfifo_depth:  coverpoint fifo_depth {
      bins depth[] = {[0 : KMAC_FIFO_DEPTH]};
      bins invalid = default;
    }
  endgroup

  covergroup sha3_status_cg with function sample(bit sha3_idle, bit sha3_absorb, bit sha3_squeeze);
    idle:     coverpoint sha3_idle;
    absorb:   coverpoint sha3_absorb;
    squeeze:  coverpoint sha3_squeeze;
  endgroup

  covergroup state_read_mask_cg with function sample(bit [TL_DBW-1:0] mask, bit share_num);
    share: coverpoint share_num;
    `MASK_CP(state_read_mask, mask)
    state_mask_share_cross: cross share, state_read_mask;
  endgroup

  covergroup sideload_cg with function sample(bit en_sideload, bit in_kmac, bit app_keymgr);
    sideload:       coverpoint en_sideload;
    kmac_mode:      coverpoint in_kmac;
    in_app_keymgr:  coverpoint app_keymgr;

    sideload_cross: cross sideload, kmac_mode, in_app_keymgr {
      bins sw_kmac_valid_sideload   = binsof(sideload) intersect {1} && binsof(kmac_mode);
      bins sw_kmac_invalid_sideload = binsof(sideload) intersect {0} && binsof(kmac_mode);
      bins app_valid_sideload       = binsof(sideload) intersect {1} && binsof(in_app_keymgr);
      bins app_invalid_sideload     = binsof(sideload) intersect {0} && binsof(in_app_keymgr);
    }
  endgroup

  covergroup error_cg with function sample(kmac_pkg::err_code_e kmac_err,
                                           kmac_pkg::kmac_cmd_e kcmd,
                                           sha3_pkg::sha3_mode_e kmode,
                                           sha3_pkg::keccak_strength_e kstrength);
    kmac_err_code: coverpoint kmac_err {
      ignore_bins ignore = {kmac_pkg::ErrNone};
      // Covered by direct sequence, if scb enabled for those seq, can remove it from this list.
      illegal_bins il = {kmac_pkg::ErrWaitTimerExpired,
                         kmac_pkg::ErrIncorrectEntropyMode,
                         kmac_pkg::ErrSwHashingWithoutEntropyReady};
    }

    cmd: coverpoint kcmd {
      ignore_bins ignore = {kmac_pkg::CmdNone};
    }

    mode: coverpoint kmode;

    strength: coverpoint kstrength;

    all_invalid_cmd_in_app_active: cross kmac_err_code, cmd {
      bins invalid_cmds = binsof(kmac_err_code) intersect {kmac_pkg::ErrSwIssuedCmdInAppActive} &&
                          binsof(cmd);

      ignore_bins ignore = !binsof(kmac_err_code) intersect {kmac_pkg::ErrSwIssuedCmdInAppActive};
    }

    all_invalid_mode_strength_cfgs: cross kmac_err_code, mode, strength {
      bins sha3_128_cfgs = binsof(kmac_err_code) intersect {kmac_pkg::ErrUnexpectedModeStrength} &&
                           binsof(mode) intersect {sha3_pkg::Sha3} &&
                           binsof(strength) intersect {sha3_pkg::L128};

      bins shake_224_invalid_cfg =
          binsof(kmac_err_code) intersect {kmac_pkg::ErrUnexpectedModeStrength} &&
          binsof(mode) intersect {sha3_pkg::Shake} &&
          binsof(strength) intersect {sha3_pkg::L224};

      bins shake_384_invalid_cfg =
          binsof(kmac_err_code) intersect {kmac_pkg::ErrUnexpectedModeStrength} &&
          binsof(mode) intersect {sha3_pkg::Shake} &&
          binsof(strength) intersect {sha3_pkg::L384};

      bins shake_512_invalid_cfg =
          binsof(kmac_err_code) intersect {kmac_pkg::ErrUnexpectedModeStrength} &&
          binsof(mode) intersect {sha3_pkg::Shake} &&
          binsof(strength) intersect {sha3_pkg::L512};

      bins cshake_224_invalid_cfg =
          binsof(kmac_err_code) intersect {kmac_pkg::ErrUnexpectedModeStrength} &&
          binsof(mode) intersect {sha3_pkg::CShake} &&
          binsof(strength) intersect {sha3_pkg::L224};

      bins cshake_384_invalid_cfg =
          binsof(kmac_err_code) intersect {kmac_pkg::ErrUnexpectedModeStrength} &&
          binsof(mode) intersect {sha3_pkg::CShake} &&
          binsof(strength) intersect {sha3_pkg::L384};

      bins cshake_512_invalid_cfg =
          binsof(kmac_err_code) intersect {kmac_pkg::ErrUnexpectedModeStrength} &&
          binsof(mode) intersect {sha3_pkg::CShake} &&
          binsof(strength) intersect {sha3_pkg::L512};

      ignore_bins ignore = !binsof(kmac_err_code) intersect {kmac_pkg::ErrUnexpectedModeStrength} ||
                           ((binsof(mode) intersect {sha3_pkg::Sha3} &&
                             !binsof(strength) intersect {sha3_pkg::L128}) ||
                            (binsof(mode) intersect {sha3_pkg::Shake, sha3_pkg::CShake} &&
                             binsof(strength) intersect {sha3_pkg::L128, sha3_pkg::L256}));
   }
  endgroup

  function void sample_cfg(bit kmac,
                           bit xof,
                           sha3_pkg::keccak_strength_e kstrength,
                           sha3_pkg::sha3_mode_e kmode,
                           kmac_pkg::key_len_e key_len,
                           bit msg_endianness,
                           bit state_endianness,
                           bit en_sideload,
                           kmac_pkg::entropy_mode_e entropy_mode,
                           bit fast_entropy);

    if (cfg.enable_masking) begin
      config_masked_cg.sample(kmac, xof, kstrength, kmode, key_len, msg_endianness,
                              state_endianness, en_sideload, entropy_mode,
                              fast_entropy);
    end else begin
      config_unmasked_cg.sample(kmac, xof, kstrength, kmode, key_len,
                                msg_endianness, state_endianness,
                                en_sideload);
    end
  endfunction

  covergroup entropy_timer_cg with function sample (bit [9:0]  prescaler,
                                                    bit [15:0] wait_timer,
                                                    bit        entropy_edn_mode);
    prescaler_val: coverpoint prescaler {
      bins zero_val   = {0};
      bins lower_val  = {[1             : {9{1'b1}} / 2 - 1]};
      bins higher_val = {[{9{1'b1}} / 2 : {9{1'b1}}]};
    }
    wait_timer_val: coverpoint wait_timer {
      bins zero_val   = {0};
      bins lower_val  = {[1              : {16{1'b1}} / 2 -1]};
      bins higher_val = {[{16{1'b1}} / 2 : {16{1'b1}}]};
    }
    entropy_edn_mode_enabled: coverpoint entropy_edn_mode;
    entropy_timer_cross: cross prescaler_val, wait_timer_val, entropy_edn_mode_enabled;
  endgroup

  function new(string name, uvm_component parent);
    kmac_app_e app_name = app_name.first;
    super.new(name, parent);
    // [instantiate covergroups here]
    msg_len_cg = new();
    output_digest_len_cg = new();
    prefix_range_cg = new();
    msgfifo_write_mask_cg = new();
    msgfifo_level_cg = new();
    sha3_status_cg = new();
    state_read_mask_cg = new();
    sideload_cg = new();
    error_cg = new();
    entropy_timer_cg = new();
    dynamic_app_config_cg = new();
    dynamic_app_request_cg = new();
    dynamic_app_session_cg = new();
    dynamic_app_stream_cg = new();
    dynamic_app_sha3_digest_cg = new();
    dynamic_app_transition_cg = new();
    dynamic_app_prefix_cg = new();
    dynamic_app_key_cg = new();
    do begin
      app_cg_wrappers[app_name] = new({app_name.name(), "_cg"});
      app_name = app_name.next;
    end while (app_name != app_name.first);
  endfunction : new

  virtual function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    // [or instantiate covergroups here]
    // Please instantiate sticky_intr_cov array of objects for all interrupts that are sticky
    // See cip_base_env_cov for details
    if (cfg.enable_masking) begin
      config_masked_cg = new();
    end else begin
      config_unmasked_cg = new();
    end
  endfunction

endclass

`undef MASK_CP
`undef SHA3_CROSS_CG
`undef XOF_CROSS_CG
`undef COMMON_CFG_CGS
