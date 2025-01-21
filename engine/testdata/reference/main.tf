data "coder_parameter" "feature_debug_enabled" {
  name         = "feature_debug_enabled"
  display_name = "Enable debug?"
  type         = "bool"

  default = true
}

variable "cache" {
  type = string
}

variable "hasDefault" {
  type = string
  default = "Hello world!"
}

data "coder_workspace_tags" "custom_workspace_tags" {
  tags = {
    "cache"   = data.coder_parameter.feature_debug_enabled.value == "true" ? var.cache : "no-cache"
    "foo"     = var.hasDefault
  }
}