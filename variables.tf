variable "application" {
  description = "The name of the application"
  default     = "sonarqube"
}

variable "owner" {
  description = "The application owner"
  default     = "owner"
}

variable "common_tags" {
  description = "A map of general tags applied to all resources"
  default     = {}
}

variable "region" {
  description = "The AWS Region where the container will be deployed"
}

variable "vpc_id" {
  description = "The VPC ID where this container will run"
}

variable "availability_zones" {
  description = "The list of availability zones where the container can be deployed"
}

variable "subnet_ids" {
  description = "List of Private Subnets IDs"
}

variable "cluster_name" {
  description = "The name of the ECS cluster"
  default     = "sonarqube"
}

variable "container_image" {
  description = "The name of the image to use in the task definition"
  default     = "sonarqube:lts"
}

variable "sonarqube_logdir" {
  description = "The directory on the EC2 host where logs should be persisted"
  default     = "/var/log/sonarqube"
}

variable "db_user" {
  description = "The name of the root user for the database"
  default     = "sonarqube"
}

variable "db_ssm_pw_loc" {
  description = "The path in parameter store where the database password is kept"
  default     = "/sonarqube/dbpassword"
}

variable "db_name" {
  description = "The name of the database"
  default     = "sonarqubedb"
}

variable "db_machine" {
  description = "The machine type of the database"
  default     = "db.t3.micro"
}

variable "db_storage" {
  description = "The storage size for the database"
  default     = 30
}

variable "db_max_storage" {
  description = "The maximum amount of storage to permit the database to grow to"
  default     = 1024
}

variable "db_backup_window" {
  description = "The database backup window in UTC"
  default     = "07:00-07:30"
}

variable "db_backup_retain_days" {
  description = "The number of days to retain backups"
  default     = 10
}

variable "db_maint_window" {
  description = "The database maintenance window in UTC"
  default     = "Mon:08:00-Mon:09:00"
}

variable "db_multi_az" {
  description = "Boolean setting to determine if the RDS instance is multi-az"
  default     = false
}

variable "db_allowed_cidr" {
  description = "A list of cidr blocks that are permitted to access the database"
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}

variable "db_major_version" {
  description = "Boolean that determines if major version upgrades are acceptable"
  default     = false
}

variable "db_minor_version" {
  description = "Boolean that determines if minor version upgrades are acceptable"
  default     = true
}

variable "db_snapshot_tags" {
  description = "Boolean that determines if tags are copied to the database snapshots"
  default     = true
}

variable "db_public" {
  description = "Boolean that determines if the RDS instance will be publicly accessible"
  default     = false
}

variable "db_log_exports" {
  description = "A list of cloudwatch log exports"
  default     = ["postgresql", "upgrade"]
}

variable "db_monitoring_interval" {
  description = "The monitoring interval for enhanced monitoring"
  default     = 0
}

variable "db_engine_version" {
  description = "The RDS database engine version of choice"
  default     = "10"
}

variable "db_skip_final_snap" {
  description = "Boolean that determines if a final snapshot is taken before the RDS instance is destroyed"
  default     = true
}

variable "db_encrypted" {
  description = "Boolean that determines if the disk storage is encrypted"
  default     = true
}

variable "db_storage_type" {
  description = "The type of storage to use"
  default     = "gp2"
}


variable "asg_prefix" {
  description = "The prefix to use for the auto-scaling group"
  default     = "sqb"
}

variable "asg_max_instances" {
  description = "Maximum number of instances in the cluster"
  default     = 1
}

variable "asg_min_instances" {
  description = "Minimum number of instances in the cluster"
  default     = 1
}

variable "asg_desired_capacity" {
  description = "Desired number of instnaces in the cluster"
  default     = 1
}

variable "asg_instance_type" {
  description = "The EC2 instance type to spin up for this auto-scaling group"
  default     = ["t3a.xlarge", "t3.xlarge", "t2.xlarge"]
}

variable "asg_ami_pattern" {
  description = "The expression to be used to search for the most recent AMI"
  default     = "amzn-ami-*-amazon-ecs-optimized"
}

variable "asg_ami_owner" {
  description = "The owner of the AMI"
  default     = "amazon"
}

variable "lb_cert_domain" {
  description = "The domain that is represented by the ACM certificate we are using"
}

variable "lb_domain_name" {
  description = "The domain name to be used for the Route53 entry"
}

variable "lb_fe_cidrs" {
  description = "CIDR blocks allowed onto the front end of the load balancer"
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}

variable "lb_internal" {
  description = "Toggle indicating internal facing load balancer"
  default     = true
}
