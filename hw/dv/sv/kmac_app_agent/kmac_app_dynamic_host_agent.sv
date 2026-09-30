// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

class kmac_app_dynamic_host_agent extends dv_base_agent #(.CFG_T       (kmac_app_agent_cfg),
                                                           .DRIVER_T    (kmac_app_dynamic_host_driver),
                                                           .SEQUENCER_T (kmac_app_host_sequencer),
                                                           .MONITOR_T   (kmac_app_monitor),
                                                           .COV_T       (kmac_app_agent_cov));
  `uvm_component_utils(kmac_app_dynamic_host_agent)

  extern function new(string name, uvm_component parent);
  extern function void build_phase(uvm_phase phase);
  extern function void connect_phase(uvm_phase phase);
endclass

function kmac_app_dynamic_host_agent::new(string name, uvm_component parent);
  super.new(name, parent);
endfunction

function void kmac_app_dynamic_host_agent::build_phase(uvm_phase phase);
  super.build_phase(phase);

  if (!uvm_config_db#(virtual kmac_app_if)::get(this, "", "vif", cfg.vif)) begin
    `uvm_fatal(`gfn, "failed to get kmac_app_if handle from uvm_config_db")
  end

  // The DUT is always the device on this link: an active dynamic agent drives OTBN requests and
  // consumes KMAC responses; a passive instance leaves both directions to the DUT/other host.
  cfg.vif.if_mode = cfg.is_active ? Host : Monitor;
  // Select concurrent request/response collection in the shared monitor. The static agents keep
  // this flag clear and continue to publish one packet paired with one complete response.
  cfg.is_dynamic_app = 1'b1;

  if (cfg.is_active && cfg.rsp_ready_policy == null) begin
    // A policy is normally constructed by kmac_env. Keep a safe default for standalone agent use.
    cfg.rsp_ready_policy = kmac_app_rsp_ready_always_policy::type_id::create("rsp_ready_policy");
  end
endfunction

function void kmac_app_dynamic_host_agent::connect_phase(uvm_phase phase);
  super.connect_phase(phase);

  if (cfg.is_active) begin
    // Sequences read accepted responses from this FIFO to decide when to terminate a session and
    // when the final finish response has been consumed.
    driver.m_rsp_port.connect(sequencer.m_rsp_fifo.analysis_export);
  end
endfunction
