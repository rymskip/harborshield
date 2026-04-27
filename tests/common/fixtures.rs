use std::collections::HashMap;

/// Test container configurations
pub struct TestContainer {
    pub name: String,
    pub image: String,
    pub labels: HashMap<String, String>,
    pub ports: Vec<String>,
    pub command: Option<Vec<String>>,
}

impl TestContainer {
    pub fn nginx(name: &str) -> Self {
        let mut labels = HashMap::new();
        labels.insert("harborshield.enabled".to_string(), "true".to_string());

        Self {
            name: name.to_string(),
            image: "alpine:latest".to_string(),
            labels,
            ports: vec!["8080".to_string()],
            command: Some(vec![
                "sh".to_string(),
                "-c".to_string(),
                r#"apk add --no-cache socat && while true; do echo -e "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!" | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -; done"#.to_string(),
            ]),
        }
    }

    pub fn nginx_with_rules(name: &str, rules: &str) -> Self {
        let mut container = Self::nginx(name);
        container
            .labels
            .insert("harborshield.rules".to_string(), rules.to_string());
        container
    }

    pub fn redis(name: &str) -> Self {
        let mut labels = HashMap::new();
        labels.insert("harborshield.enabled".to_string(), "true".to_string());

        Self {
            name: name.to_string(),
            image: "redis:alpine".to_string(),
            labels,
            ports: vec!["6379".to_string()],
            command: None,
        }
    }

    pub fn postgres(name: &str) -> Self {
        let mut labels = HashMap::new();
        labels.insert("harborshield.enabled".to_string(), "true".to_string());

        Self {
            name: name.to_string(),
            image: "postgres:alpine".to_string(),
            labels,
            ports: vec!["5432".to_string()],
            command: None,
        }
    }

    pub fn netcat_server(name: &str, port: u16) -> Self {
        let mut labels = HashMap::new();
        labels.insert("harborshield.enabled".to_string(), "true".to_string());

        Self {
            name: name.to_string(),
            image: "alpine:latest".to_string(),
            labels,
            ports: vec![port.to_string()],
            command: Some(vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("while true; do nc -l -p {} -e echo 'OK'; done", port),
            ]),
        }
    }

    pub fn client_container(name: &str) -> Self {
        Self {
            name: name.to_string(),
            image: "alpine:latest".to_string(),
            labels: HashMap::new(),
            ports: vec![],
            command: Some(vec!["sleep".to_string(), "3600".to_string()]),
        }
    }
}

/// Sample harborshield rules configurations
pub struct SampleRules;

impl SampleRules {
    pub fn allow_all_tcp() -> &'static str {
        r#"
mapped_ports:
  - port: 80
    protocol: tcp
    allow: true
"#
    }

    pub fn allow_localhost_only() -> &'static str {
        r#"
mapped_ports:
  - port: 80
    protocol: tcp
    allow: true
    localhost_only: true
"#
    }

    pub fn allow_specific_ips() -> &'static str {
        r#"
mapped_ports:
  - port: 80
    protocol: tcp
    allow: true
    source_ips:
      - "172.16.0.0/12"
      - "10.0.0.0/8"
"#
    }

    pub fn deny_all() -> &'static str {
        r#"
mapped_ports:
  - port: 80
    protocol: tcp
    allow: false
"#
    }

    pub fn rate_limited() -> &'static str {
        r#"
mapped_ports:
  - port: 80
    protocol: tcp
    allow: true
    rate_limit: "10/minute"
"#
    }

    pub fn multi_port() -> &'static str {
        r#"
mapped_ports:
  - port: 80
    protocol: tcp
    allow: true
  - port: 443
    protocol: tcp
    allow: true
  - port: 8080
    protocol: tcp
    allow: false
"#
    }

    pub fn established_connections() -> &'static str {
        r#"
mapped_ports:
  - port: 80
    protocol: tcp
    allow: true
outbound_rules:
  - action: allow
    protocol: tcp
    port: 443
    track_established: true
"#
    }

    pub fn container_to_container() -> &'static str {
        r#"
container_rules:
  - container: "other-service"
    protocol: tcp
    port: 8080
    action: allow
"#
    }

    pub fn compose_service() -> &'static str {
        r#"
container_rules:
  - container: "backend"
    protocol: tcp
    port: 3000
    action: allow
  - container: "database"
    protocol: tcp
    port: 5432
    action: allow
"#
    }

    pub fn udp_rules() -> &'static str {
        r#"
mapped_ports:
  - port: 53
    protocol: udp
    allow: true
  - port: 123
    protocol: udp
    allow: true
    source_ips:
      - "10.0.0.0/8"
"#
    }
}

// We need to test all of this
// # controls traffic from localhost or external networks to a container on mapped ports
// mapped_ports:
//   # controls traffic from localhost
//   localhost:
//     # required; allow traffic from localhost or not
//     allow: false
//     # optional; log new inbound traffic that this rule will match
//     log_prefix: ""
//     # optional; settings that allow you to filter traffic further if desired
//     verdict:
//       # optional; a chain to jump to after matching traffic. This applies to new and established
//       # inbound traffic, and established outbound traffic
//       chain: ""
//       # optional; the userspace nfqueue to send new outbound packets to
//       queue: 0
//       # optional; the userspace nfqueue to send established inbound packets to. Required if
//       # 'output_est_queue' is set
//       input_est_queue: 0
//       # optional; the userspace nfqueue to send established inbound packets to. Required if
//       # 'input_est_queue' is set
//       output_est_queue: 0
//   # controls traffic from external networks (from any non-loopback network interface)
//   external:
//     # required; allow external traffic or not
//     allow: false
//     # optional; log new inbound traffic that this rule will match
//     log_prefix: ""
//     # optional; a list of IP addresses, CIDRs, or ranges of IP addresses to allow traffic from
//     ips: []
//     # optional; settings that allow you to filter traffic further if desired
//     verdict:
//       # optional; a chain to jump to after matching traffic. This applies to new and established
//       # inbound traffic, and established outbound traffic
//       chain: ""
//       # optional; the userspace nfqueue to send new outbound packets to
//       queue: 0
//       # optional; the userspace nfqueue to send established inbound packets to. Required if
//       # 'output_est_queue' is set
//       input_est_queue: 0
//       # optional; the userspace nfqueue to send established inbound packets to. Required if
//       # 'input_est_queue' is set
//       output_est_queue: 0
// # controls traffic from a container to localhost, another container, or the internet
// output:
//     # optional; log new outbound traffic that this rule will match
//   - log_prefix: ""
//     # optional; a Docker network traffic will be allowed out of. If unset, will default to all
//     # networks the container is a member of. Required if 'container' is set
//     network: ""
//     # optional; a list of IP addresses, CIDRs, or ranges of IP addresses to allow traffic to
//     ips: []
//     # optional; a container to allow traffic to. This can be either the name of the container or
//     # the service name of the container is docker compose is used
//     container: ""
//     # required; either 'tcp' or 'udp'
//     proto: ""
//     # optional; a list of source ports to allow traffic to. Can be a single port or a
//     # range of ports.
//     src_ports: []
//     # optional; a list of destination ports to allow traffic to. Can be a single port or a
//     # range of ports.
//     dst_ports: []
//     # optional; settings that allow you to filter traffic further if desired
//     verdict:
//       # optional; a chain to jump to after matching traffic. This applies to new and established
//       # inbound traffic, and established outbound traffic
//       chain: ""
//       # optional; the userspace nfqueue to send new outbound packets to
//       queue: 0
//       # optional; the userspace nfqueue to send established inbound packets to. Required if
//       # 'output_est_queue' is set
//       input_est_queue: 0
//       # optional; the userspace nfqueue to send established inbound packets to. Required if
//       # 'input_est_queue' is set
//       output_est_queue: 0

/// Docker compose configurations for testing
pub struct ComposeConfigs;

impl ComposeConfigs {
    /// Test mapped_ports configurations - localhost with all options
    pub fn mapped_ports_localhost_full() -> &'static str {
        r#"
services:
  web:
    image: alpine:latest
    command: [sh, -c, "apk add --no-cache socat && while true; do echo -e 'HTTP/1.1 200 OK\r\n\r\nOK' | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -; done"]
    ports:
      - "38080:8080"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          localhost:
            allow: true
            log_prefix: "localhost-in"
            verdict:
              queue: 100
              input_est_queue: 101
              output_est_queue: 102
"#
    }

    /// Test mapped_ports configurations - external with IP filtering
    pub fn mapped_ports_external_ips() -> &'static str {
        r#"
services:
  api:
    image: alpine:latest
    command: [sh, -c, "apk add --no-cache socat && while true; do echo -e 'HTTP/1.1 200 OK\r\n\r\nAPI' | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -; done"]
    ports:
      - "38081:8080"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          localhost:
            allow: false
          external:
            allow: true
            log_prefix: "external-api"
            ips:
              - "192.168.1.0/24"
              - "10.0.0.0/8"
              - "172.16.5.10"
            verdict:
              chain: "rate-limit"
"#
    }

    /// Test output rules - all options including container, network, IPs
    pub fn output_rules_comprehensive() -> &'static str {
        r#"
services:
  app:
    image: alpine:latest
    command: [sh, -c, "apk add --no-cache socat && while true; do echo 'app' | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -; done"]
    ports:
      - "28090:8080"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          localhost:
            allow: false
          external:
            allow: false
        output:
          # DNS with logging
          - log_prefix: "dns-query"
            proto: udp
            dst_ports: ["53"]
            ips: ["8.8.8.8", "8.8.4.4"]
          # Container communication with specific network
          - network: backend
            container: database
            proto: tcp
            dst_ports: ["5432"]
            src_ports: ["32768-65535"]
          # HTTPS with port ranges
          - proto: tcp
            dst_ports: ["443", "8443"]
            ips: ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
            verdict:
              chain: "tls-inspect"
          # Custom service with queue
          - proto: tcp
            dst_ports: ["9000"]
    networks:
      - default
      - backend

  database:
    image: postgres:alpine
    environment:
      POSTGRES_PASSWORD: test
    labels:
      harborshield.enabled: "true"
    networks:
      - backend

networks:
  default:
    driver: bridge
  backend:
    driver: bridge
"#
    }

    /// Test UDP-specific rules
    pub fn udp_services() -> &'static str {
        r#"
services:
  dns:
    image: alpine:latest
    command: [sh, -c, "apk add --no-cache socat && while true; do socat -u UDP-LISTEN:53,reuseaddr,fork EXEC:'/bin/echo DNS'; done"]
    ports:
      - "35353:53/udp"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          localhost:
            allow: true
          external:
            allow: true
            ips: ["10.0.0.0/8"]

  ntp:
    image: alpine:latest
    command: [sh, -c, "apk add --no-cache socat && while true; do socat -u UDP-LISTEN:123,reuseaddr,fork EXEC:'/bin/echo NTP'; done"]
    ports:
      - "30123:123/udp"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          external:
            allow: true
            log_prefix: "ntp-sync"
"#
    }

    /// Test verdict chain jumps
    pub fn verdict_chain_jumps() -> &'static str {
        r#"
services:
  web_chain:
    image: alpine:latest
    command: [sh, -c, "apk add --no-cache socat && while true; do echo -e 'HTTP/1.1 200 OK\r\n\r\nOK' | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -; done"]
    ports:
      - "38088:8080"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          localhost:
            allow: true
            log_prefix: "localhost-chain"
            verdict:
              chain: "custom-localhost"
          external:
            allow: true
            log_prefix: "external-chain"
            verdict:
              chain: "custom-external"
        output:
          - proto: tcp
            dst_ports: ["443"]
            verdict:
              chain: "tls-inspect"
"#
    }

    /// Test verdict queues
    pub fn verdict_queues() -> &'static str {
        r#"
services:
  monitor:
    image: alpine:latest
    command: [sh, -c, "apk add --no-cache socat && while true; do echo 'monitored' | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -; done"]
    ports:
      - "38082:8080"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          localhost:
            allow: true
            verdict:
              queue: 1000
          external:
            allow: true
            verdict:
              queue: 2000
              input_est_queue: 2001
              output_est_queue: 2002
        output:
          - proto: tcp
            dst_ports: ["443"]
            verdict:
              chain: "tls-decrypt"
           
"#
    }

    /// Test complex multi-container dependencies
    pub fn complex_dependencies() -> &'static str {
        r#"
services:
  lb:
    image: alpine:latest
    command: [sh, -c, "apk add --no-cache socat && while true; do echo 'LB' | socat -t 1 TCP-LISTEN:80,reuseaddr,fork -; done"]
    ports:
      - "30080:80"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          external:
            allow: true
        output:
          - network: default
            container: web1
            proto: tcp
            dst_ports: ["8080"]
          - network: default
            container: web2
            proto: tcp
            dst_ports: ["8080"]

  web1:
    image: alpine:latest
    command: [sh, -c, "apk add --no-cache socat && while true; do echo 'Web1' | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -; done"]
    depends_on: [cache, db]
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        output:
          - network: default
            container: cache
            proto: tcp
            dst_ports: ["6379"]
          - network: default
            container: db
            proto: tcp
            dst_ports: ["3306"]

  web2:
    image: alpine:latest
    command: [sh, -c, "apk add --no-cache socat && while true; do echo 'Web2' | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -; done"]
    depends_on: [cache, db]
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        output:
          - network: default
            container: cache
            proto: tcp
            dst_ports: ["6379"]
          - network: default
            container: db
            proto: tcp
            dst_ports: ["3306"]

  cache:
    image: redis:alpine
    labels:
      harborshield.enabled: "true"

  db:
    image: mariadb:latest
    environment:
      MYSQL_ROOT_PASSWORD: test
    labels:
      harborshield.enabled: "true"
"#
    }

    /// Test IP ranges and CIDR notations
    pub fn ip_filtering() -> &'static str {
        r#"
services:
  restricted:
    image: alpine:latest
    command: [sh, -c, "apk add --no-cache socat && while true; do echo 'restricted' | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -; done"]
    ports:
      - "38083:8080"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          external:
            allow: true
            ips:
              - "192.168.0.0/16"
              - "10.0.0.100-10.0.0.200"
              - "172.16.0.0/12"
              - "203.0.113.42"
        output:
          - proto: tcp
            dst_ports: ["443"]
            ips:
              - "1.1.1.1"
              - "8.8.8.8"
              - "208.67.222.222-208.67.222.223"
"#
    }

    /// Test port ranges and multiple protocols
    pub fn port_ranges() -> &'static str {
        r#"
services:
  multiport:
    image: alpine:latest
    command: [sh, -c, "apk add --no-cache socat && while true; do echo 'multi' | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -; done"]
    ports:
      - "38084:8080"
      - "38085:8081"
      - "38086:8082"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          localhost:
            allow: true
          external:
            allow: true
        output:
          - proto: tcp
            src_ports: ["1024-65535"]
            dst_ports: ["80", "443", "8080-8090"]
            ips: ["1.1.1.1", "8.8.8.8"]
          - proto: udp
            dst_ports: ["53", "123", "500-600"]
"#
    }

    /// Test logging configurations
    pub fn logging_rules() -> &'static str {
        r#"
services:
  logged:
    image: alpine:latest
    command: [sh, -c, "apk add --no-cache socat && while true; do echo 'logged' | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -; done"]
    ports:
      - "38087:8080"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          localhost:
            allow: true
            log_prefix: "LOCAL-IN"
          external:
            allow: true
            log_prefix: "EXT-IN"
            ips: ["192.168.1.0/24"]
        output:
          - log_prefix: "DNS-OUT"
            proto: udp
            dst_ports: ["53"]
          - log_prefix: "HTTPS-OUT"
            proto: tcp
            dst_ports: ["443"]
          - log_prefix: "CONTAINER-OUT"
            network: default
            container: other
            proto: tcp
            dst_ports: ["9000"]

  other:
    image: alpine:latest
    command: [sh, -c, "apk add --no-cache socat && while true; do echo 'other' | socat -t 1 TCP-LISTEN:9000,reuseaddr,fork -; done"]
    labels:
      harborshield.enabled: "true"
"#
    }

    /// This is an official example from the Harborshield github
    pub fn miniflux() -> &'static str {
        r#"
services:
  miniflux:
    depends_on:
      - miniflux_db
    environment:
      - DATABASE_URL=postgres://miniflux:secret@miniflux_db/miniflux?sslmode=disable
      - RUN_MIGRATIONS=1
      - CREATE_ADMIN=1
      - ADMIN_USERNAME=admin
      - ADMIN_PASSWORD=password
    image: miniflux/miniflux:latest
    labels:
      harborshield.enabled: true
      harborshield.rules: |
        mapped_ports:
          # allow traffic to port 80 from localhost
          localhost:
            allow: true
          # allow traffic to port 80 from LAN
          external:
            allow: true
            ips:
              - "192.168.1.0/24"
        output:
          # allow postgres connections
          - network: default
            container: miniflux_db
            proto: tcp
            dst_ports:
              - 5432
          # allow DNS requests
          - log_prefix: "dns"
            proto: udp
            dst_ports:
              - 53
          # allow HTTPS requests
          - log_prefix: "https"
            proto: tcp
            dst_ports:
              - 443
    ports:
      - "18081:8080/tcp"

  miniflux_db:
    environment:
      - POSTGRES_USER=miniflux
      - POSTGRES_PASSWORD=secret
    image: postgres:alpine
    labels:
      # no rules specified, drop all traffic
      harborshield.enabled: true"#
    }

    /// This is an official example from the Harborshield github
    pub fn client() -> &'static str {
        r#"
services:
  client:
    container_name: client
    command: "80"
    image: ghcr.io/capnspacehook/eavesdropper
    labels:
      harborshield.enabled: true
      # Client only allows tcp:756 toward server. server also listens on 80
      # and 9001 — those should be dropped by harborshield. The framework
      # turns this into a real packet probe (nc with timeout).
      harborshield.test.expect_blocked: "server:80,server:9001"
      harborshield.rules: |
        mapped_ports:
          localhost:
            allow: true
        output:
          - proto: udp
            dst_ports:
              - 53
          - ips:
              - 1.1.1.1
            proto: tcp
            dst_ports:
              - 80
          - proto: tcp
            dst_ports:
              - 443
          - network: default
            container: server
            proto: tcp
            dst_ports:
              - 756
          - proto: tcp
            ips:
              - 2.2.2.2-3.3.3.3
              - 4.4.4.4-5.5.5.5
            dst_ports:
              - 1-5
              - 10-20
    ports:
      - "18082:80"

  server:
    container_name: server
    command: "80 756 9001"
    depends_on:
      - client
    image: ghcr.io/capnspacehook/eavesdropper
    labels:
      harborshield.enabled: true
      harborshield.rules: |
        mapped_ports:
          external:
            allow: true
    ports:
      - "18083:80"
      - "19001:9001"

  tester:
    command: "8443"
    image: ghcr.io/capnspacehook/eavesdropper
    network_mode: host
"#
    }
    pub fn basic_web_app() -> &'static str {
        r#"
services:
  frontend:
    image: alpine:latest
    command:
      - sh
      - -c
      - |
        apk add --no-cache socat && \
        while true; do
          echo -e "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!" | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -
        done
    ports:
      - "28080:8080"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          localhost:
            allow: true
          external:
            allow: true
        output:
          - network: default
            container: backend
            proto: tcp
            dst_ports:
              - 3000

  backend:
    image: alpine:latest
    command: 
      - sh
      - -c
      - |
        apk add --no-cache socat && \
        while true; do
          echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK" | socat -t 1 TCP-LISTEN:3000,reuseaddr,fork -
        done
    expose:
      - "3000"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        output:
          - network: default
            container: database
            proto: tcp
            dst_ports:
              - 5432

  database:
    image: postgres:alpine
    environment:
      POSTGRES_PASSWORD: testpass
    expose:
      - "5432"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          localhost:
            allow: false
          external:
            allow: false

networks:
  default:
    driver: bridge
"#
    }

    pub fn microservices() -> &'static str {
        r#"
services:
  gateway:
    image: alpine:latest
    command:
      - sh
      - -c
      - |
        apk add --no-cache socat && \
        while true; do
          echo -e "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nGateway" | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -
        done
    ports:
      - "28084:8080"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          localhost:
            allow: true
          external:
            allow: true
        output:
          - network: default
            container: auth
            proto: tcp
            dst_ports:
              - 8080
          - network: default
            container: api
            proto: tcp
            dst_ports:
              - 8080

  auth:
    image: alpine:latest
    command:
      - sh
      - -c
      - |
        apk add --no-cache socat && \
        while true; do
          echo -e "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nAuth" | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -
        done
    expose:
      - "8080"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        output:
          - network: default
            container: redis
            proto: tcp
            dst_ports:
              - 6379

  api:
    image: alpine:latest
    command:
      - sh
      - -c
      - |
        apk add --no-cache socat && \
        while true; do
          echo -e "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nAPI" | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -
        done
    expose:
      - "8080"
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        output:
          - network: default
            container: postgres
            proto: tcp
            dst_ports:
              - 5432
          - network: default
            container: redis
            proto: tcp
            dst_ports:
              - 6379

  redis:
    image: redis:alpine
    expose:
      - "6379"
    labels:
      harborshield.enabled: "true"

  postgres:
    image: postgres:alpine
    environment:
      POSTGRES_PASSWORD: testpass
    expose:
      - "5432"
    labels:
      harborshield.enabled: "true"

networks:
  default:
    driver: bridge
"#
    }

    /// Test multiple networks with cross-network dependencies
    pub fn multi_network_dependencies() -> &'static str {
        r#"
services:
  # Frontend services on DMZ network
  web_frontend:
    image: alpine:latest
    command:
      - sh
      - -c
      - |
        apk add --no-cache socat && \
        while true; do
          echo -e "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nFrontend" | socat -t 1 TCP-LISTEN:80,reuseaddr,fork -
        done
    ports:
      - "30080:80"
    networks:
      - dmz
      - app_tier
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        mapped_ports:
          localhost:
            allow: false
          external:
            allow: true
            ips:
              - "10.0.0.0/8"
              - "172.16.0.0/12"
              - "192.168.0.0/16"
        output:
          # Can talk to API gateway on app tier
          - network: app_tier
            container: api_gateway
            proto: tcp
            dst_ports: ["8080"]
          # Can talk to static assets on DMZ
          - network: dmz
            container: static_assets
            proto: tcp
            dst_ports: ["80"]
          # DNS lookups
          - proto: udp
            dst_ports: ["53"]
            ips: ["8.8.8.8", "8.8.4.4"]

  static_assets:
    image: alpine:latest
    command:
      - sh
      - -c
      - |
        apk add --no-cache socat && \
        while true; do
          echo -e "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nStatic" | socat -t 1 TCP-LISTEN:80,reuseaddr,fork -
        done
    expose:
      - "80"
    networks:
      - dmz
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        # Only accepts connections from web frontend
        output:
          - proto: tcp
            dst_ports: ["443"]
            ips: ["192.0.2.0/24"]  # CDN IPs

  # Application tier services
  api_gateway:
    image: alpine:latest
    command:
      - sh
      - -c
      - |
        apk add --no-cache socat && \
        while true; do
          echo -e "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nAPI" | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -
        done
    expose:
      - "8080"
    networks:
      - app_tier
      - backend_tier
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        output:
          # Can talk to auth service on app tier
          - network: app_tier
            container: auth_service
            proto: tcp
            dst_ports: ["8080"]
          # Can talk to user service on backend tier
          - network: backend_tier
            container: user_service
            proto: tcp
            dst_ports: ["9000"]
          # Can talk to order service on backend tier
          - network: backend_tier
            container: order_service
            proto: tcp
            dst_ports: ["9001"]

  auth_service:
    image: alpine:latest
    command:
      - sh
      - -c
      - |
        apk add --no-cache socat && \
        while true; do
          echo -e "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nAuth" | socat -t 1 TCP-LISTEN:8080,reuseaddr,fork -
        done
    expose:
      - "8080"
    networks:
      - app_tier
      - cache_tier
      - data_tier
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        output:
          # Can talk to session cache
          - network: cache_tier
            container: session_cache
            proto: tcp
            dst_ports: ["6379"]
          # Can talk to auth database on data tier
          - network: data_tier
            container: auth_db
            proto: tcp
            dst_ports: ["5432"]

  # Backend tier services
  user_service:
    image: alpine:latest
    command:
      - sh
      - -c
      - |
        apk add --no-cache socat && \
        while true; do
          echo -e "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nUser" | socat -t 1 TCP-LISTEN:9000,reuseaddr,fork -
        done
    expose:
      - "9000"
    networks:
      - backend_tier
      - data_tier
      - cache_tier
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        output:
          # Can talk to user database
          - network: data_tier
            container: user_db
            proto: tcp
            dst_ports: ["5432"]
          # Can talk to cache
          - network: cache_tier
            container: data_cache
            proto: tcp
            dst_ports: ["6379"]

  order_service:
    image: alpine:latest
    command:
      - sh
      - -c
      - |
        apk add --no-cache socat && \
        while true; do
          echo -e "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nOrder" | socat -t 1 TCP-LISTEN:9001,reuseaddr,fork -
        done
    expose:
      - "9001"
    networks:
      - backend_tier
      - data_tier
      - message_tier
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        output:
          # Can talk to order database
          - network: data_tier
            container: order_db
            proto: tcp
            dst_ports: ["5432"]
          # Can publish to message queue
          - network: message_tier
            container: message_queue
            proto: tcp
            dst_ports: ["5672"]

  # Cache tier
  session_cache:
    image: redis:alpine
    expose:
      - "6379"
    networks:
      - cache_tier
    labels:
      harborshield.enabled: "true"

  data_cache:
    image: redis:alpine
    expose:
      - "6379"
    networks:
      - cache_tier
    labels:
      harborshield.enabled: "true"

  # Data tier
  auth_db:
    image: postgres:alpine
    environment:
      POSTGRES_PASSWORD: authpass
    expose:
      - "5432"
    networks:
      - data_tier
    labels:
      harborshield.enabled: "true"

  user_db:
    image: postgres:alpine
    environment:
      POSTGRES_PASSWORD: userpass
    expose:
      - "5432"
    networks:
      - data_tier
    labels:
      harborshield.enabled: "true"

  order_db:
    image: postgres:alpine
    environment:
      POSTGRES_PASSWORD: orderpass
    expose:
      - "5432"
    networks:
      - data_tier
    labels:
      harborshield.enabled: "true"

  # Message tier
  message_queue:
    image: rabbitmq:alpine
    expose:
      - "5672"
    networks:
      - message_tier
    labels:
      harborshield.enabled: "true"

  # Worker that processes messages (connects to multiple networks)
  order_processor:
    image: alpine:latest
    command:
      - sh
      - -c
      - |
        apk add --no-cache socat && \
        while true; do
          sleep 30
        done
    networks:
      - message_tier
      - data_tier
      - external_api
    labels:
      harborshield.enabled: "true"
      harborshield.rules: |
        output:
          # Can consume from message queue
          - network: message_tier
            container: message_queue
            proto: tcp
            dst_ports: ["5672"]
          # Can update order database
          - network: data_tier
            container: order_db
            proto: tcp
            dst_ports: ["5432"]
          # Can call external payment API
          - proto: tcp
            dst_ports: ["443"]
            ips: ["198.51.100.0/24"]  # Payment provider IPs

networks:
  default:
    driver: bridge
    ipam:
      config:
        - subnet: 172.19.0.0/24
  dmz:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
  app_tier:
    driver: bridge
    ipam:
      config:
        - subnet: 172.21.0.0/24
  backend_tier:
    driver: bridge
    ipam:
      config:
        - subnet: 172.22.0.0/24
  cache_tier:
    driver: bridge
    ipam:
      config:
        - subnet: 172.23.0.0/24
  data_tier:
    driver: bridge
    ipam:
      config:
        - subnet: 172.24.0.0/24
  message_tier:
    driver: bridge
    ipam:
      config:
        - subnet: 172.25.0.0/24
  external_api:
    driver: bridge
    ipam:
      config:
        - subnet: 172.26.0.0/24
"#
    }
}
