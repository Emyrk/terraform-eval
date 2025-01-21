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