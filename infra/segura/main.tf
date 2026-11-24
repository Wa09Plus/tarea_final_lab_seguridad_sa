resource "aws_security_group" "internaldesk_api_sg" {
  name        = "internaldesk-api-sg-secure"
  description = "Security group restringido para InternalDesk API en red interna"

  ingress {
    description = "Acceso a la API FastAPI solo desde la red corporativa interna"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "Salida HTTPS limitada a servicios internos autorizados"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_network_interface" "internaldesk_api_eni" {
  subnet_id       = "subnet-0123456789abcdef0"
  security_groups = [aws_security_group.internaldesk_api_sg.id]
}