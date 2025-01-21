mock_provider "mock-instance" {
  mock_resource "mock-instance" {
    defaults = {
      status = "started"
    }
  }
}

# mock_data "mock-color" {
#   defaults = {
#     color = "blue"
#   }
# }


run "blue_is_best" {
  command = plan
  assert {
    condition     = data.mock-color.favorite-color == "blue"
    error_message = "S3 bucket name did not match expected"
  }
}