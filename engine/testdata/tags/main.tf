locals {
  arg_string = "foo"
  arg_bool = true
  arg_number = 42
  arg_list = ["a", "b", "c"]
  arg_mixed_list = ["a", 42, true]
}

/* Big comment */
resource "mock-instance" "foo" {
  // Comment
  name = "name-foo" # Comment
  color = data.fake_data.favorite-color.color
}

data "mock-color" "favorite-color" {
  user = "me"
}

data "coder_parameter" "feature_debug_enabled" {
  name         = "feature_debug_enabled"
  display_name = "Enable debug?"
  type         = "bool"

  default = true
}

data "coder_workspace_tags" "custom_workspace_tags" {
  tags = {
    "cluster" = "developers"
    "foo"     = local.arg_string
    "debug"   = data.coder_parameter.feature_debug_enabled.value
    "cache"   = data.coder_parameter.feature_debug_enabled.value == "true" ? "nix-with-cache" : "no-cache"
    "list"    = join(",", local.arg_list)
    "color"   = data.mock_color.favorite-color.color
  }
}