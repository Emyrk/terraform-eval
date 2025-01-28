terraform {
  required_providers {
    coder = {
      source = "coder/coder"
    }
  }
}

module "code-server" {
  count    = data.coder_workspace.me.start_count
  source   = "registry.coder.com/modules/code-server/coder"
  version  = "1.0.26"
  agent_id = coder_agent.main.id
}

data "coder_workspace" "me" {}
resource "coder_agent" "main" {
}