// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Drives one dynamic application session: configuration, message, and (for XOF sessions) an
// explicit termination request. Responses are consumed from the host sequencer FIFO so termination
// is sent only after the requested number of digest chunks has been accepted.
class kmac_app_dynamic_host_seq extends dv_base_seq #(.REQ         (kmac_app_req_item),
                                                      .CFG_T       (kmac_app_agent_cfg),
                                                      .SEQUENCER_T (kmac_app_host_sequencer));
  `uvm_object_utils(kmac_app_dynamic_host_seq)

  // Sent in the first accepted request. The RTL ignores prefix_mode for dynamic interfaces and
  // selects prefix source from mode, but initialize it deterministically for packed bus data.
  kmac_pkg::app_ses_config_t session_cfg = '{prefix_mode: 1'b0,
                                               mode: kmac_pkg::AppShake,
                                               kstrength: sha3_pkg::L256,
                                               en_xof: 1'b1};
  int unsigned msg_size_bytes = 1;
  // For XOF runs, consume this many response beats before asking the DUT to stop squeezing.
  int unsigned xof_chunks_before_terminate = 2;

  extern function new(string name = "");
  extern virtual task body();
  extern local task send_req(int unsigned num_bytes, bit last, bit [MsgWidth-1:0] data_s0,
                             bit [MsgWidth-1:0] data_s1, bit override_data);
  extern local task send_message();
  extern local function int unsigned get_digest_chunk_count();
  extern local task consume_until_finish();
endclass

function kmac_app_dynamic_host_seq::new(string name = "");
  super.new(name);
endfunction

task kmac_app_dynamic_host_seq::body();
  kmac_app_req_item req;
  bit [MsgWidth-1:0] config_data_s0 = '0;
  int unsigned config_bytes = ($bits(kmac_pkg::app_ses_config_t) + 7) / 8;
  kmac_app_rsp_item rsp;
  int unsigned chunks_received = 0;
  int unsigned chunks_to_terminate;

  // Reject unsupported request combinations early; the DUT reports these as service errors, but
  // this sequence currently models only valid dynamic sessions.
  if (session_cfg.en_xof && !(session_cfg.mode inside {kmac_pkg::AppShake,
                                                      kmac_pkg::AppCShake})) begin
    `uvm_fatal(get_full_name(), "Dynamic XOF is only supported for SHAKE/cSHAKE sessions")
  end
  if ((session_cfg.mode inside {kmac_pkg::AppSHA3, kmac_pkg::AppKMAC}) && session_cfg.en_xof) begin
    `uvm_fatal(get_full_name(), "SHA3 and KMAC sessions must have en_xof=0")
  end

  // RTL interprets the first OTBN request's low data_s0 bits as app_ses_config_t. Its strobe must
  // cover every byte of that packed struct, and req_last must remain low because this is not input
  // message data and does not end the session.
  config_data_s0[$bits(kmac_pkg::app_ses_config_t)-1:0] = session_cfg;
  send_req(config_bytes, 1'b0, config_data_s0, '0, 1'b1);

  send_message();

  // Non-XOF functions have a fixed response count determined by mode/strength. XOF functions can
  // continue squeezing indefinitely, so the host deliberately chooses a finite count instead.
  chunks_to_terminate = session_cfg.en_xof ? xof_chunks_before_terminate :
                        get_digest_chunk_count();
  while (chunks_received < chunks_to_terminate) begin
    p_sequencer.m_rsp_fifo.get(rsp);
    if (rsp.m_finish) begin
      `uvm_fatal(get_full_name(), "Dynamic session finished before termination")
    end
    if (rsp.m_error) break;
    chunks_received++;
  end

  // Every dynamic session, including non-XOF sessions, ends with a distinct empty termination
  // request after its output has been consumed. The request's req_last is distinct from the
  // message-ending req_last above; the RTL uses this later marker to stop response production.
  send_req(0, 1'b1, '0, '0, 1'b1);
  consume_until_finish();
endtask

task kmac_app_dynamic_host_seq::send_message();
  int unsigned bytes_remaining = msg_size_bytes;
  int unsigned max_bytes_per_word = MsgWidth / 8;

  // This agent-level sequence controls framing and byte count. Non-config message payloads are
  // randomized by send_req(); the KMAC scoreboard observes those bus bytes as its digest input.
  if (bytes_remaining == 0) begin
    // A zero-byte message still needs one final message request. This is separate from the later
    // dynamic-session termination request, which is sent after digest output.
    send_req(0, 1'b1, '0, '0, 1'b0);
    return;
  end

  while (bytes_remaining > 0) begin
    // Request items are at most one MsgWidth beat. Only the final data beat ends the message;
    // the subsequent session termination beat is emitted by body().
    int unsigned num_bytes = (bytes_remaining > max_bytes_per_word) ?
                             max_bytes_per_word : bytes_remaining;
    bit last = (num_bytes == bytes_remaining);
    send_req(num_bytes, last, '0, '0, 1'b0);
    bytes_remaining -= num_bytes;
  end
endtask

function int unsigned kmac_app_dynamic_host_seq::get_digest_chunk_count();
  // Dynamic responses carry DynAppDigestW bits each (64 bits in this KMAC configuration). SHA3-224
  // is rounded up to four beats by the RTL; SHAKE/cSHAKE use one full Keccak rate per squeeze.
  case (session_cfg.mode)
    kmac_pkg::AppSHA3: begin
      case (session_cfg.kstrength)
        sha3_pkg::L224: return 4;
        sha3_pkg::L256: return 4;
        sha3_pkg::L384: return 6;
        sha3_pkg::L512: return 8;
        default: `uvm_fatal(get_full_name(), "Invalid SHA3 strength in dynamic session")
      endcase
    end
    kmac_pkg::AppKMAC: return 8;
    kmac_pkg::AppShake, kmac_pkg::AppCShake: begin
      case (session_cfg.kstrength)
        sha3_pkg::L128: return 21;
        sha3_pkg::L256: return 17;
        default: `uvm_fatal(get_full_name(), "Invalid XOF strength in dynamic session")
      endcase
    end
    default: `uvm_fatal(get_full_name(), "Invalid dynamic application mode")
  endcase
  return 0;
endfunction

task kmac_app_dynamic_host_seq::send_req(int unsigned num_bytes, bit last,
                                         bit [MsgWidth-1:0] data_s0,
                                         bit [MsgWidth-1:0] data_s1,
                                         bit override_data);
  kmac_app_req_item req = kmac_app_req_item::type_id::create("req");

  start_item(req);
  // Randomize the item first to retain normal randomized request data/delay behavior, then replace
  // only fields with protocol-defined content (config and termination payloads).
  if (!req.randomize() with {
        m_num_bytes == local::num_bytes;
        m_last == local::last;
        cfg.req_delay_min <= m_delay; m_delay <= cfg.req_delay_max;
      }) begin
    `uvm_fatal(get_full_name(), "Failed to randomize dynamic request")
  end
  if (override_data) begin
    req.m_data_s0 = data_s0;
    req.m_data_s1 = data_s1;
  end
  finish_item(req);
endtask

task kmac_app_dynamic_host_seq::consume_until_finish();
  kmac_app_rsp_item rsp;
  bit finished = 0;

  while (!finished) begin
    // Continue draining after termination: digest/error beats can already be pipelined ahead of the
    // finish acknowledgement. Finish itself is observed from the accepted-response FIFO.
    p_sequencer.m_rsp_fifo.get(rsp);
    finished = rsp.m_finish;
  end
endtask
