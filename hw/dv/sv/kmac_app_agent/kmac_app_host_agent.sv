// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

class kmac_app_host_agent extends dv_base_agent #(.CFG_T       (kmac_app_agent_cfg),
                                                  .DRIVER_T    (kmac_app_host_driver),
                                                  .SEQUENCER_T (kmac_app_host_sequencer),
                                                  .MONITOR_T   (kmac_app_monitor),
                                                  .COV_T       (kmac_app_agent_cov));
  `uvm_component_utils(kmac_app_host_agent)

  extern function new(string name, uvm_component parent);
  extern function void build_phase(uvm_phase phase);
  extern function void connect_phase(uvm_phase phase);
endclass

function kmac_app_host_agent::new(string name, uvm_component parent);
  super.new(name, parent);
endfunction

function void kmac_app_host_agent::build_phase(uvm_phase phase);
  super.build_phase(phase);

  // Get the handle to the interface
  if (!uvm_config_db#(virtual kmac_app_if)::get(this, "", "vif", cfg.vif)) begin
    `uvm_fatal(`gfn, "failed to get kmac_app_if handle from uvm_config_db")
  end

  // Configure the interface to match the agent.
  cfg.vif.if_mode = cfg.is_active ? Host : Monitor;

  if (cfg.is_active && cfg.rsp_ready_policy == null) begin
    string policy_name = "always";
    void'($value$plusargs("kmac_app_rsp_ready_policy=%0s", policy_name));
    case (policy_name)
      "always": cfg.rsp_ready_policy =
          kmac_app_rsp_ready_always_policy::type_id::create("rsp_ready_policy");
      "always_with_dip": cfg.rsp_ready_policy =
          kmac_app_rsp_ready_always_with_dip_policy::type_id::create("rsp_ready_policy");
      "random": cfg.rsp_ready_policy =
          kmac_app_rsp_ready_random_policy::type_id::create("rsp_ready_policy");
      "when_valid": cfg.rsp_ready_policy =
          kmac_app_rsp_ready_when_valid_policy::type_id::create("rsp_ready_policy");
      default: `uvm_fatal(`gfn, $sformatf(
          "Unknown +kmac_app_rsp_ready_policy value: %0s", policy_name))
    endcase
  end
endfunction

function void kmac_app_host_agent::connect_phase(uvm_phase phase);
  super.connect_phase(phase);

  if (cfg.is_active) begin
    driver.m_rsp_port.connect(sequencer.m_rsp_fifo.analysis_export);
  end
endfunction
