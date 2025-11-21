output "vpc_id" {
  value = aws_vpc.main.id
}

output "nlb_dns" {
  value = aws_lb.nlb.dns_name
}

output "haproxy_instances" {
  value = { for k,v in aws_instance.haproxy : k => v.id }
}

output "web_instances_gie" {
  value = { for k,v in aws_instance.web_gie : k => v.id }
}

output "web_instances_gic" {
  value = { for k,v in aws_instance.web_gic : k => v.id }
}

output "pf_key_public" {
  value = tls_private_key.pf_key.public_key_openssh
}

output "pf_key_private_pem" {
  description = "Private key PEM. Save this securely and then remove from outputs."
  value       = tls_private_key.pf_key.private_key_pem
  sensitive   = true
}