//! A realistic stack started with `docker compose`, using compose-local service and network
//! names in its rules the way users write them.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::support::{Container, Failure, Listener, Origin, docker, e2e, tcp};

e2e! {
    /// web is public on 18090 and may call app; app may call db; nothing else crosses.
    async fn compose_stack_enforces_each_service_boundary(scenario) {
        let project = scenario.name("stack");
        let sandbox = scenario.sandbox.clone();
        let labels = |extra: &[(&str, String)]| -> Value {
            let mut map: BTreeMap<String, String> = scenario.resource_labels().into_iter().collect();
            for (key, value) in extra {
                map.insert((*key).to_owned(), value.clone());
            }
            json!(map)
        };
        let web_rules = json!({
            "mapped_ports": { "external": { "allow": true } },
            "output": [{ "container": "app", "network": "backend", "proto": "tcp", "dst_ports": [8081] }],
        });
        let app_rules = json!({
            "output": [{ "container": "db", "network": "backend", "proto": "tcp", "dst_ports": [5432] }],
        });
        let image = crate::support::FIXTURE_IMAGE;
        let enabled = ("harborshield.enabled", "true".to_owned());
        let compose = json!({
            "name": project,
            "services": {
                "web": {
                    "image": image, "hostname": "web", "command": ["tcp:8080"],
                    "ports": ["18090:8080"], "networks": ["frontend", "backend"],
                    "labels": labels(&[enabled.clone(), ("harborshield.rules", web_rules.to_string())]),
                },
                "app": {
                    "image": image, "hostname": "app", "command": ["tcp:8081"], "networks": ["backend"],
                    "labels": labels(&[enabled.clone(), ("harborshield.rules", app_rules.to_string())]),
                },
                "db": {
                    "image": image, "hostname": "db", "command": ["tcp:5432"], "networks": ["backend"],
                    "labels": labels(std::slice::from_ref(&enabled)),
                },
            },
            "networks": {
                "frontend": { "labels": labels(&[]) },
                "backend": { "labels": labels(&[]) },
            },
        });
        let file = scenario.data_dir().join("compose.json");
        std::fs::write(&file, compose.to_string())
            .map_err(|error| Failure::context(format!("write {}", file.display()), error))?;
        let file = file
            .to_str()
            .ok_or_else(|| Failure::new("compose file path is not UTF-8"))?
            .to_owned();

        scenario.start_daemon().await?;
        docker(&["compose", "--file", &file, "up", "--detach", "--wait"]).await?;

        let web = Container::existing(&format!("{project}-web-1")).await?;
        let app = Container::existing(&format!("{project}-app-1")).await?;
        let db = Container::existing(&format!("{project}-db-1")).await?;
        web.wait_for_listeners(&[Listener::Tcp(8080)]).await?;
        app.wait_for_listeners(&[Listener::Tcp(8081)]).await?;
        db.wait_for_listeners(&[Listener::Tcp(5432)]).await?;
        for container in [&web, &app, &db] {
            scenario.wait_until_managed(container).await?;
        }

        let backend = crate::support::Network { name: format!("{project}_backend") };
        let app_ip = app.ip_on(&backend).await?;
        let db_ip = db.ip_on(&backend).await?;

        tcp(Origin::External { sandbox: &sandbox, source: sandbox.external_addr }, sandbox.host_addr, 18090)
            .expect_connected("web", 8080)
            .await?;
        tcp(Origin::Container(&web.name), app_ip, 8081).expect_connected("app", 8081).await?;
        tcp(Origin::Container(&app.name), db_ip, 5432).expect_connected("db", 5432).await?;

        tcp(Origin::Container(&web.name), db_ip, 5432).expect_dropped().await?;
        tcp(Origin::Container(&db.name), app_ip, 8081).expect_dropped().await
    }
}
