# main.tf

terraform {
  required_providers {
    coder = {
      source = "coder/coder"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "3.0.2"
    }
  }
}

data "coder_workspace_tags" "custom_workspace_tags" {
  tags = {
    "foo" = docker_image.ubuntu.repo_digest
    "bar" = docker_image.centos.repo_digest
    "qux" = "quux"
  }
}


# Pulls the image
resource "docker_image" "ubuntu" {
  name = "ubuntu:latest"
}

resource "docker_image" "centos" {
  name = "centos:latest"
}

