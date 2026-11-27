packer {
  required_version = ">= 1.10.0"
  required_plugins {
    amazon = {
      version = ">= 1.3.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "instance_type" {
  type    = string
  default = "c7g.xlarge"
}

variable "architecture" {
  type    = string
  default = "arm64"
}

variable "backplane_hub_version" {
  type    = string
  default = "latest"
}

variable "backplane_kicad_version" {
  type    = string
  default = "10.99.0-bp.13.5"
}

variable "solidcraft_version" {
  type    = string
  default = "0.50.0"
}

variable "solidcraft_sha256_x86_64" {
  type    = string
  default = "b0c63f45fe58ab13c40145132b21fdc309f45e294301f1ba525050aa99575920"
}

variable "solidcraft_sha256_aarch64" {
  type    = string
  default = "5a5c6e87533f70de2ad0fcc23c7b36f45144ccf9ded77ff0099cbbea39b4c337"
}

variable "backplane_release_base_url" {
  type    = string
  default = "https://releases.backplane.works"
}

source "amazon-ebs" "boat_vm" {
  ami_name        = "backplane-enterprise-boat-{{timestamp}}"
  ami_description = "Managed Backplane Enterprise Boat VM (Backplane + Backplane_KiCad + Zero-Tailscale Outbound mTLS Relay Agent)"
  instance_type   = var.instance_type
  region          = var.aws_region
  ssh_username    = "ubuntu"
  ebs_optimized   = true
  encrypt_boot    = true

  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-${var.architecture}-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"] # Canonical
  }

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 60
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }

  tags = {
    Name                   = "backplane-enterprise-boat"
    BackplaneHubVersion    = var.backplane_hub_version
    BackplaneKiCadVersion  = var.backplane_kicad_version
    SolidCraftVersion      = var.solidcraft_version
    ZeroTailscaleMtlsRelay = "true"
  }
}

build {
  name    = "backplane-boat-vm"
  sources = ["source.amazon-ebs.boat_vm"]

  provisioner "file" {
    source      = "${path.root}/../agent/boat-relay-agent.sh"
    destination = "/tmp/boat-relay-agent.sh"
  }

  provisioner "file" {
    source      = "${path.root}/../systemd/bp-boat-relay-agent.service"
    destination = "/tmp/bp-boat-relay-agent.service"
  }

  provisioner "file" {
    source      = "${path.root}/../systemd/bp-boat-cert-renew.service"
    destination = "/tmp/bp-boat-cert-renew.service"
  }

  provisioner "file" {
    source      = "${path.root}/../systemd/bp-boat-cert-renew.timer"
    destination = "/tmp/bp-boat-cert-renew.timer"
  }

  provisioner "shell" {
    environment_vars = [
      "BACKPLANE_HUB_VERSION=${var.backplane_hub_version}",
      "BACKPLANE_KICAD_VERSION=${var.backplane_kicad_version}",
      "BACKPLANE_RELEASE_BASE_URL=${var.backplane_release_base_url}",
      "SOLIDCRAFT_VERSION=${var.solidcraft_version}",
      "SOLIDCRAFT_ARCH=${var.architecture == "arm64" ? "aarch64" : "x86_64"}",
      "SOLIDCRAFT_SHA256=${var.architecture == "arm64" ? var.solidcraft_sha256_aarch64 : var.solidcraft_sha256_x86_64}",
    ]
    inline = [
      "set -euo pipefail",
      "sudo apt-get update",
      "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl jq git xvfb socat websocat ufw unattended-upgrades",
      "SC_TGZ=\"solidcraft-${SOLIDCRAFT_VERSION}-linux-${SOLIDCRAFT_ARCH}.tar.gz\"",
      "curl --fail --silent --show-error --location \"https://github.com/tangency-labs/solidcraft/releases/download/v${SOLIDCRAFT_VERSION}/${SC_TGZ}\" -o \"/tmp/${SC_TGZ}\"",
      "echo \"${SOLIDCRAFT_SHA256}  /tmp/${SC_TGZ}\" | sha256sum -c -",
      "tar -xzf \"/tmp/${SC_TGZ}\" -C /tmp \"solidcraft-${SOLIDCRAFT_VERSION}-linux-${SOLIDCRAFT_ARCH}/bin/solidcraft-cli\"",
      "sudo install -o root -g root -m 0755 \"/tmp/solidcraft-${SOLIDCRAFT_VERSION}-linux-${SOLIDCRAFT_ARCH}/bin/solidcraft-cli\" /usr/local/bin/solidcraft-cli",
      "rm -rf \"/tmp/${SC_TGZ}\" \"/tmp/solidcraft-${SOLIDCRAFT_VERSION}-linux-${SOLIDCRAFT_ARCH}\"",
      "sudo useradd --system --create-home --home-dir /var/lib/backplane --shell /usr/sbin/nologin boat",
      "sudo install -d -o boat -g boat -m 0750 /etc/backplane-boat /etc/backplane-boat/certs /var/lib/backplane/workspace /run/backplane-boat",
      "sudo install -o root -g root -m 0755 /tmp/boat-relay-agent.sh /usr/local/bin/boat-relay-agent",
      "sudo install -o root -g root -m 0644 /tmp/bp-boat-relay-agent.service /etc/systemd/system/bp-boat-relay-agent.service",
      "sudo install -o root -g root -m 0644 /tmp/bp-boat-cert-renew.service /etc/systemd/system/bp-boat-cert-renew.service",
      "sudo install -o root -g root -m 0644 /tmp/bp-boat-cert-renew.timer /etc/systemd/system/bp-boat-cert-renew.timer",
      "sudo rm -f /tmp/boat-relay-agent.sh /tmp/bp-boat-*.service /tmp/bp-boat-*.timer",
      "printf '{\"backplane_hub\":\"%s\",\"backplane_kicad\":\"%s\",\"solidcraft\":\"%s\",\"release_base\":\"%s\"}\\n' \"$BACKPLANE_HUB_VERSION\" \"$BACKPLANE_KICAD_VERSION\" \"$SOLIDCRAFT_VERSION\" \"$BACKPLANE_RELEASE_BASE_URL\" | sudo tee /etc/backplane-boat/manifest.json >/dev/null",
      "sudo ufw --force reset",
      "sudo ufw default deny incoming",
      "sudo ufw default allow outgoing",
      "sudo ufw --force enable",
      "sudo systemctl disable --now ssh.service ssh.socket || true",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable bp-boat-relay-agent.service bp-boat-cert-renew.timer",
      "sudo apt-get clean && sudo rm -rf /var/lib/apt/lists/*"
    ]
  }
}
