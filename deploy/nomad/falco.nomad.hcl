# Nomad system job running Falco with the gvisor plugin on every client.
# Clients must run Docker with the runsc runtime configured with
# --pod-init-config=/etc/falco/gvisor-pod-init.json.
job "falco" {
  type        = "system"
  datacenters = ["*"]

  group "falco" {
    task "falco" {
      driver = "docker"

      config {
        image        = "ghcr.io/falcosecurity/falco-gvisor:latest"
        privileged   = true
        pid_mode     = "host"
        volumes = [
          "/run/falco:/run/falco",
          "/var/run/docker.sock:/var/run/docker.sock:ro",
          "/var/run/docker.sock:/host/var/run/docker.sock:ro",
          "/usr/local/bin/runsc:/usr/local/bin/runsc:ro",
          "/run/docker/runtime-runc/moby:/run/docker/runtime-runc/moby",
          "/proc:/host/proc:ro",
          "/etc:/host/etc:ro",
        ]
      }

      env {
        HOST_ROOT = "/host"
      }

      resources {
        cpu    = 500
        memory = 512
      }
    }
  }
}
