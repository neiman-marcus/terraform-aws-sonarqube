provider "aws" {
  region = var.region
}

terraform {
  required_version = ">= 0.12"
  required_providers {
    aws = ">= 2.24.0"
  }
}

data "aws_caller_identity" "current" {}

data "aws_route53_zone" "rt53domain" {
  name = var.lb_domain_name
}

data "aws_acm_certificate" "cert_name" {
  domain      = var.lb_cert_domain
  types       = ["AMAZON_ISSUED"]
  most_recent = true
}

data "aws_iam_policy_document" "ecs_service_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "asg_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com", "ecs-tasks.amazonaws.com"]
    }
  }
}

data "aws_ssm_parameter" "db_pass" {
  name            = var.db_ssm_pw_loc
  with_decryption = true
}

data "aws_ami" "linux" {
  most_recent = true
  filter {
    name   = "name"
    values = [var.asg_ami_pattern]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = [var.asg_ami_owner]
}

data "template_file" "asg_user_data" {
  template = templatefile("${path.module}/user_data.sh.tpl",
    {
      clusterName = var.cluster_name
      logDir      = var.sonarqube_logdir
    }
  )
}

data "template_cloudinit_config" "config" {
  gzip          = true
  base64_encode = true
  part {
    filename     = "user_data.sh"
    content_type = "text/x-shellscript"
    content      = data.template_file.asg_user_data.rendered
  }
}

resource "aws_launch_template" "asg_template" {
  name_prefix = var.asg_prefix
  description = "Template used to spin up Sonarqube EC2 tweaked instances"

  disable_api_termination = false

  ebs_optimized = true

  iam_instance_profile {
    arn = aws_iam_instance_profile.asg_profile.arn
  }

  image_id = data.aws_ami.linux.id

  instance_initiated_shutdown_behavior = "terminate"

  monitoring {
    enabled = true
  }

  placement {
    tenancy = "default"
  }

  vpc_security_group_ids = [aws_security_group.backend_sg.id]

  tag_specifications {
    resource_type = "instance"
    tags          = var.common_tags
  }

  user_data = data.template_cloudinit_config.config.rendered
}

resource "aws_autoscaling_group" "asg" {
  availability_zones  = var.availability_zones
  desired_capacity    = var.asg_desired_capacity
  max_size            = var.asg_max_instances
  min_size            = var.asg_min_instances
  vpc_zone_identifier = var.subnet_ids
  enabled_metrics     = ["GroupMinSize", "GroupMaxSize", "GroupDesiredCapacity", "GroupInServiceInstances", "GroupPendingInstances", "GroupStandbyInstances", "GroupTerminatingInstances", "GroupTotalInstances"]
  mixed_instances_policy {
    instances_distribution {
      on_demand_base_capacity                  = 0
      on_demand_percentage_above_base_capacity = 0
      spot_instance_pools                      = 1
    }
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.asg_template.id
        version            = "$Latest"
      }
      dynamic "override" {
        for_each = var.asg_instance_type
        content {
          instance_type = override.value
        }
      }
    }
  }
  tags = [
    {
      key                 = "Name"
      value               = "${var.asg_prefix}-asg"
      propagate_at_launch = false
    },
    {
      key                 = "Owner"
      value               = var.owner
      propagate_at_launch = false
    },
    {
      key                 = "Application"
      value               = var.application
      propagate_at_launch = false
    }
  ]
}

resource "aws_iam_instance_profile" "asg_profile" {
  name = "${var.asg_prefix}-asg-profile"
  role = aws_iam_role.asg_role.name
  path = "/"
}

resource "aws_iam_role" "asg_role" {
  name               = "${var.asg_prefix}-asg-role"
  path               = "/"
  assume_role_policy = data.aws_iam_policy_document.asg_policy.json
  tags = merge(
    var.common_tags,
    {
      "Name" = "${var.asg_prefix}-asg-role",
    }
  )
}

# allow ECS to launch containers on this instance
resource "aws_iam_role_policy_attachment" "asg_container_role_policy_attach" {
  role       = aws_iam_role.asg_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

# allow ECS to run tasks on this instance
resource "aws_iam_role_policy_attachment" "asg_execution_role_policy_attach" {
  role       = aws_iam_role.asg_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# allow this instance access to RDS
resource "aws_iam_role_policy_attachment" "asg_rds_role_policy_attach" {
  role       = aws_iam_role.asg_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonRDSDataFullAccess"
}

# allow a user to log in via SSM (plus other SSM stuff) because no ssh keys are set
resource "aws_iam_role_policy_attachment" "asg_ssm_role_policy_attach" {
  role       = aws_iam_role.asg_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM"
}

# allow writes to cloudwatch
resource "aws_iam_role_policy_attachment" "asg_cloudwatch_role_policy_attach" {
  role       = aws_iam_role.asg_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# allow auto-scaling
resource "aws_iam_role_policy_attachment" "asg_autoscale_role_policy_attach" {
  role       = aws_iam_role.asg_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2SpotFleetAutoscaleRole"
}

# allow decrypt password in SSM Parameter Store
# NOTE: that for this to work the password has to be stored at /${var.db_ssm_pw_loc}/
#       and the key is the default aws ssm key
resource "aws_iam_policy" "asg_ssm_access_policy" {
  name        = "${var.asg_prefix}-ssm-access"
  path        = "/"
  description = "Allow this ECS to access SSM"
  policy      = <<EOF
{
     "Version": "2012-10-17",
     "Statement": [
         {
             "Effect": "Allow",
             "Action": [
                 "ssm:DescribeParameters"
             ],
             "Resource": "*"
         },
         {
             "Sid": "Statement1",
             "Effect": "Allow",
             "Action": [
                 "ssm:GetParameters"
             ],
             "Resource": [
                 "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter${var.db_ssm_pw_loc}"
             ]
         },
         {
             "Sid": "Statement2",
             "Effect": "Allow",
             "Action": [
                 "kms:Decrypt"
             ],
             "Resource": [
                 "arn:aws:kms:${var.region}:${data.aws_caller_identity.current.account_id}:key/aws/ssm"
             ]
         }
     ]
 }
EOF
}

resource "aws_iam_role_policy_attachment" "asg_ssm_access_policy_attach" {
  role       = aws_iam_role.asg_role.name
  policy_arn = aws_iam_policy.asg_ssm_access_policy.arn
}

resource "aws_db_instance" "dbinstance" {
  name                            = var.db_name
  username                        = var.db_user
  password                        = data.aws_ssm_parameter.db_pass.value
  allocated_storage               = var.db_storage
  allow_major_version_upgrade     = var.db_major_version
  auto_minor_version_upgrade      = var.db_minor_version
  backup_retention_period         = var.db_backup_retain_days
  backup_window                   = var.db_backup_window
  copy_tags_to_snapshot           = var.db_snapshot_tags
  db_subnet_group_name            = aws_db_subnet_group.subnet_group.name
  enabled_cloudwatch_logs_exports = var.db_log_exports
  engine                          = "postgres"
  engine_version                  = var.db_engine_version
  identifier                      = var.db_name
  instance_class                  = var.db_machine
  maintenance_window              = var.db_maint_window
  max_allocated_storage           = var.db_max_storage
  monitoring_interval             = var.db_monitoring_interval
  multi_az                        = var.db_multi_az
  publicly_accessible             = var.db_public
  skip_final_snapshot             = var.db_skip_final_snap
  storage_encrypted               = var.db_encrypted
  storage_type                    = var.db_storage_type
  vpc_security_group_ids          = [aws_security_group.db_sg.id]
  tags = merge(
    var.common_tags,
    {
      "Name" = var.db_name
    }
  )
}

resource "aws_db_subnet_group" "subnet_group" {
  name       = "${var.db_name}-subnet-group"
  subnet_ids = var.subnet_ids

  tags = merge(
    var.common_tags,
    {
      "Name" = "${var.db_name}-subnet-group",
    },
  )
}

resource "aws_security_group" "db_sg" {
  name        = "${var.asg_prefix}-db-sg"
  description = "Allow postgres database Connections"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.common_tags,
    {
      "Name" = "${var.asg_prefix}-db-sg",
    },
  )
}

resource "aws_security_group_rule" "allow_postgres" {
  type        = "ingress"
  from_port   = 5432
  to_port     = 5432
  protocol    = "tcp"
  cidr_blocks = var.db_allowed_cidr
  description = "Allow access to postgress"

  security_group_id = aws_security_group.db_sg.id

}

resource "aws_ecs_cluster" "ecs_cluster" {
  name = var.cluster_name
}

resource "aws_ecs_task_definition" "task_definition" {
  family             = "${var.asg_prefix}-family"
  execution_role_arn = aws_iam_role.asg_role.arn
  container_definitions = templatefile("${path.module}/task_definition.json.tpl",
    {
      awsAccount     = data.aws_caller_identity.current.account_id,
      awsRegion      = var.region,
      clusterName    = var.cluster_name,
      appOwner       = var.owner,
      appName        = var.application,
      dbName         = var.db_name,
      dbUser         = var.db_user,
      dbPassword     = var.db_ssm_pw_loc,
      dbEndpoint     = aws_db_instance.dbinstance.endpoint,
      taskRoleArn    = aws_iam_role.asg_role.arn,
      taskFamily     = "${var.asg_prefix}-family"
      containerImage = var.container_image
    }
  )
  volume {
    name      = "sonarqube_logs"
    host_path = var.sonarqube_logdir
  }
}

resource "aws_ecs_service" "service_definition" {
  name            = "${var.asg_prefix}-service"
  iam_role        = aws_iam_role.ecs_service_role.arn
  cluster         = aws_ecs_cluster.ecs_cluster.id
  task_definition = aws_ecs_task_definition.task_definition.arn
  desired_count   = 1
  depends_on      = [aws_iam_role.ecs_service_role, aws_lb.load_balancer]

  load_balancer {
    target_group_arn = aws_lb_target_group.target_group.arn
    container_name   = var.cluster_name
    container_port   = 9000
  }
}

resource "aws_iam_role" "ecs_service_role" {
  name               = "ecs-service-role"
  path               = "/"
  assume_role_policy = data.aws_iam_policy_document.ecs_service_policy.json
  tags = merge(
    var.common_tags,
    {
      "Name" = "${var.asg_prefix}-service-role",
    },
  )
}

resource "aws_iam_role_policy_attachment" "ecs_container_role_policy_attach" {
  role       = aws_iam_role.ecs_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceRole"
}

resource "aws_cloudwatch_log_group" "log_group" {
  name              = "sonarqube-ecs-logs"
  retention_in_days = 90
  tags = merge(
    var.common_tags,
    {
      "Name" = "sonarqube-ecs-logs",
    },
  )
}

resource "aws_route53_record" "host" {
  zone_id = data.aws_route53_zone.rt53domain.zone_id
  name    = "${var.asg_prefix}.${var.lb_domain_name}"
  type    = "A"

  alias {
    name                   = aws_lb.load_balancer.dns_name
    zone_id                = aws_lb.load_balancer.zone_id
    evaluate_target_health = false
  }
}

resource "aws_lb_target_group" "target_group" {
  name     = "${var.asg_prefix}-tg"
  port     = 9000
  protocol = "HTTP"
  vpc_id   = var.vpc_id
  health_check {
    healthy_threshold   = 5
    unhealthy_threshold = 2
    interval            = 30
    matcher             = 200
    path                = "/"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
  }
  tags = merge(
    var.common_tags,
    {
      "Name" = "${var.asg_prefix}-tg",
    },
  )
}

resource "aws_lb" "load_balancer" {
  name               = "${var.asg_prefix}-lb"
  internal           = var.lb_internal
  load_balancer_type = "application"
  security_groups    = [aws_security_group.frontend_sg.id, aws_security_group.backend_sg.id]
  subnets            = var.subnet_ids

  enable_deletion_protection = false

  tags = merge(
    var.common_tags,
    {
      "Name" = "${var.asg_prefix}-lb"
    }
  )
}

resource "aws_lb_listener" "lb_listener" {
  load_balancer_arn = aws_lb.load_balancer.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = data.aws_acm_certificate.cert_name.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.target_group.arn
  }
}

resource "aws_security_group" "backend_sg" {
  name        = "${var.asg_prefix}-backend-sg"
  description = "Allow connections from the load balancer to the container or EC2 instance"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
  }

  tags = merge(
    var.common_tags,
    {
      "Name" = "${var.asg_prefix}-backend-sg"
    },
  )
}

resource "aws_security_group" "frontend_sg" {
  name        = "${var.asg_prefix}-frontend-sg"
  description = "Allow access to the load balancer"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.common_tags,
    {
      "Name" = "${var.asg_prefix}-frontend-sg"
    }
  )
}

resource "aws_security_group_rule" "allow_frontend" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = var.lb_fe_cidrs
  description = "Allow into front door"

  security_group_id = aws_security_group.frontend_sg.id
}
