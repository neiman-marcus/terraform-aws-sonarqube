output "db_name" {
  value = aws_db_instance.dbinstance.name
}

output "db_username" {
  value = aws_db_instance.dbinstance.username
}

output "db_endpoint" {
  value = aws_db_instance.dbinstance.endpoint
}

output "db_jdbc" {
  value = "jdbc:postgresql://${aws_db_instance.dbinstance.endpoint}/sonar"
}

output "db_backup_retention_period" {
  value = aws_db_instance.dbinstance.backup_retention_period
}

output "db_backup_window" {
  value = aws_db_instance.dbinstance.backup_window
}

output "db_maintenance_window" {
  value = aws_db_instance.dbinstance.maintenance_window
}

output "db_sg_id" {
  value = aws_security_group.db_sg.id
}

output "asg_ami_id" {
  value = data.aws_ami.linux.id
}

output "lb_fe_sg_id" {
  value = aws_security_group.fe_sg.id
}

output "lb_be_sg_id" {
  value = aws_security_group.be_sg.id
}

output "lb_listener_id" {
  value = aws_lb_listener.lb_listener.id
}

output "lb_id" {
  value = aws_lb.load_balancer.id
}

output "lb_name" {
  value = aws_lb.load_balancer.name
}

output "lb_tg_id" {
  value = aws_lb_target_group.target_group.id
}

output "lb_tg_name" {
  value = aws_lb_target_group.target_group.name
}

output "lb_dns_name" {
  value = aws_lb.load_balancer.dns_name
}

output "lb_zone_id" {
  value = aws_lb.load_balancer.zone_id
}

output "lb_arn" {
  value = aws_lb.load_balancer.arn
}

output "lb_url" {
  value = "https://${aws_route53_record.www.fqdn}"
}

output "ecs_cluster_id" {
  value = aws_ecs_cluster.ecs_cluster.id
}

output "ecs_taskdef_id" {
  value = aws_ecs_task_definition.task_definition.id
}

output "ecs_servicedef_id" {
  value = aws_ecs_service.service_definition.id
}

output "ecs_servicedef_name" {
  value = aws_ecs_service.service_definition.name
}

output "ecs_role_name" {
  value = aws_iam_role.ecs_service_role.name
}
