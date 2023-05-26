terraform {
  required_providers {
    cosign = {
      source = "chainguard-dev/cosign"
    }
  }
}

variable "region" {
  default = "us-west-2"
}

variable "subnet" {
  type = string
}

provider "aws" {
  region = var.region
}

data "cosign_verify" "example" {
  image  = "cgr.dev/chainguard/nginx"
  policy = file("${path.module}/nginx.policy.yaml")
}

resource "aws_iam_role" "example" {
  name = "terraform-ecs-cosign"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "ecs.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      },{
        "Effect": "Allow",
        "Principal": {
          "Service": "ecs-tasks.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  })
}

// From https://aws.amazon.com/premiumsupport/knowledge-center/ecs-tasks-pull-images-ecr-repository/
resource "aws_iam_role_policy_attachment" "allow_ecs" {
  role       = aws_iam_role.example.id
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_ecs_cluster" "cluster" {
  name = "tf-cosign-cluster"
}

resource "aws_ecs_service" "bar" {
  name            = "bar"
  cluster         = aws_ecs_cluster.cluster.id
  task_definition = aws_ecs_task_definition.bar.arn
  desired_count   = 2
  capacity_provider_strategy {
    base              = 1
    capacity_provider = "FARGATE"
    weight            = 100
  }
  network_configuration {
    assign_public_ip = true
    subnets = [var.subnet]
  }
}

resource "aws_ecs_task_definition" "bar" {
  family                   = "bar"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  execution_role_arn       = aws_iam_role.example.arn
  cpu                      = 1024
  memory                   = 2048
  container_definitions    = jsonencode([
    {
      "name": "bar",
      "image": data.cosign_verify.example.verified_ref,
      "cpu": 1024,
      "memory": 2048,
      "essential": true
    }
  ])
}

resource "aws_ecs_cluster_capacity_providers" "cluster" {
  cluster_name = aws_ecs_cluster.cluster.name
  capacity_providers = ["FARGATE"]
  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider = "FARGATE"
  }
}

