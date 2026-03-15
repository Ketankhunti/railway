//! Alert rule CRUD and alert event listing endpoints.

use std::sync::Arc;
use axum::extract::{Path, Query, State};
use axum::Json;

use crate::app::SharedState;
use crate::error::ApiError;
use crate::models::{
    AlertEventResponse, AlertEventsQuery, AlertRuleResponse, ApiResponse,
    CreateAlertRuleRequest,
};

/// GET /api/v1/alerts/rules?project_id=...
///
/// List all alert rules for a project.
pub async fn list_rules(
    State(state): State<SharedState>,
    Query(query): Query<AlertEventsQuery>,
) -> Result<Json<ApiResponse<Vec<AlertRuleResponse>>>, ApiError> {
    let store = state.alert_store.read().await;
    let rules: Vec<AlertRuleResponse> = store
        .list(&query.project_id)
        .into_iter()
        .cloned()
        .collect();
    Ok(Json(ApiResponse::new(rules)))
}

/// POST /api/v1/alerts/rules
///
/// Create a new alert rule.
pub async fn create_rule(
    State(state): State<SharedState>,
    Json(body): Json<CreateAlertRuleRequest>,
) -> Result<Json<ApiResponse<AlertRuleResponse>>, ApiError> {
    if body.name.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    if body.name.len() > 256 {
        return Err(ApiError::BadRequest("name too long (max 256 chars)".into()));
    }
    if body.project_id.len() > 128 || body.service_id.len() > 128 {
        return Err(ApiError::BadRequest("project_id and service_id must be <= 128 chars".into()));
    }

    let valid_types = ["threshold", "anomaly", "rate_of_change"];
    if !valid_types.contains(&body.rule_type.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "invalid rule_type '{}', must be one of: {:?}",
            body.rule_type, valid_types
        )));
    }

    let valid_severities = ["critical", "warning", "info"];
    if !valid_severities.contains(&body.severity.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "invalid severity '{}', must be one of: {:?}",
            body.severity, valid_severities
        )));
    }

    let rule = AlertRuleResponse {
        id: String::new(), // assigned by store
        project_id: body.project_id.clone(),
        name: body.name.clone(),
        service_id: body.service_id.clone(),
        rule_type: body.rule_type.clone(),
        config: body.config.clone(),
        severity: body.severity.clone(),
        enabled: true,
        cooldown_secs: body.cooldown_secs.unwrap_or(300),
    };

    let mut store = state.alert_store.write().await;
    let id = store.add(rule);

    let created = store.get(&id).unwrap().clone();
    Ok(Json(ApiResponse::new(created)))
}

/// PUT /api/v1/alerts/rules/{rule_id}
///
/// Update an existing alert rule.
pub async fn update_rule(
    State(state): State<SharedState>,
    Path(rule_id): Path<String>,
    Json(body): Json<CreateAlertRuleRequest>,
) -> Result<Json<ApiResponse<AlertRuleResponse>>, ApiError> {
    // Validate inputs (same checks as create_rule)
    if body.name.is_empty() {
        return Err(ApiError::BadRequest("name is required".into()));
    }
    if body.name.len() > 256 {
        return Err(ApiError::BadRequest("name too long (max 256 chars)".into()));
    }

    let valid_types = ["threshold", "anomaly", "rate_of_change"];
    if !valid_types.contains(&body.rule_type.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "invalid rule_type '{}', must be one of: {:?}",
            body.rule_type, valid_types
        )));
    }

    let valid_severities = ["critical", "warning", "info"];
    if !valid_severities.contains(&body.severity.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "invalid severity '{}', must be one of: {:?}",
            body.severity, valid_severities
        )));
    }

    let updated = AlertRuleResponse {
        id: rule_id.clone(),
        project_id: body.project_id,
        name: body.name,
        service_id: body.service_id,
        rule_type: body.rule_type,
        config: body.config,
        severity: body.severity,
        enabled: true,
        cooldown_secs: body.cooldown_secs.unwrap_or(300),
    };

    let mut store = state.alert_store.write().await;
    if store.update(&rule_id, updated) {
        let result = store.get(&rule_id).unwrap().clone();
        Ok(Json(ApiResponse::new(result)))
    } else {
        Err(ApiError::NotFound(format!("rule {} not found", rule_id)))
    }
}

/// DELETE /api/v1/alerts/rules/{rule_id}
///
/// Delete an alert rule.
pub async fn delete_rule(
    State(state): State<SharedState>,
    Path(rule_id): Path<String>,
) -> Result<Json<ApiResponse<String>>, ApiError> {
    let mut store = state.alert_store.write().await;
    if store.delete(&rule_id) {
        Ok(Json(ApiResponse::new("deleted".into())))
    } else {
        Err(ApiError::NotFound(format!("rule {} not found", rule_id)))
    }
}

/// GET /api/v1/alerts/events?project_id=...&status=...&severity=...&limit=...
///
/// List alert events (firing/resolved).
pub async fn list_events(
    State(state): State<SharedState>,
    Query(query): Query<AlertEventsQuery>,
) -> Result<Json<ApiResponse<Vec<AlertEventResponse>>>, ApiError> {
    let store = state.alert_event_store.read().await;
    let limit = query.limit.unwrap_or(50) as usize;
    let events: Vec<AlertEventResponse> = store
        .list(
            &query.project_id,
            query.status.as_deref(),
            query.severity.as_deref(),
            limit,
        )
        .into_iter()
        .cloned()
        .collect();
    Ok(Json(ApiResponse::new(events)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;

    #[tokio::test]
    async fn create_and_list_rules() {
        let state = Arc::new(AppState::new());

        // Create
        let body = CreateAlertRuleRequest {
            project_id: "proj_demo".into(),
            name: "High Error Rate".into(),
            service_id: "svc_api".into(),
            rule_type: "threshold".into(),
            config: serde_json::json!({
                "metric": "error_rate",
                "operator": ">",
                "value": 0.05,
                "window_secs": 300,
                "min_requests": 100
            }),
            severity: "critical".into(),
            cooldown_secs: Some(600),
        };

        let result = create_rule(State(state.clone()), Json(body)).await.unwrap();
        let rule = &result.0.data;
        assert!(rule.id.starts_with("rule_"));
        assert_eq!(rule.name, "High Error Rate");
        assert_eq!(rule.severity, "critical");
        assert_eq!(rule.cooldown_secs, 600);
        assert!(rule.enabled);

        // List
        let query = AlertEventsQuery {
            project_id: "proj_demo".into(),
            status: None,
            severity: None,
            limit: None,
        };
        let result = list_rules(State(state.clone()), Query(query)).await.unwrap();
        assert_eq!(result.0.data.len(), 1);
    }

    #[tokio::test]
    async fn create_rule_validation() {
        let state = Arc::new(AppState::new());

        // Empty name
        let body = CreateAlertRuleRequest {
            project_id: "proj".into(),
            name: "".into(),
            service_id: "svc".into(),
            rule_type: "threshold".into(),
            config: serde_json::json!({}),
            severity: "critical".into(),
            cooldown_secs: None,
        };
        let result = create_rule(State(state.clone()), Json(body)).await;
        assert!(result.is_err());

        // Invalid rule_type
        let body = CreateAlertRuleRequest {
            project_id: "proj".into(),
            name: "test".into(),
            service_id: "svc".into(),
            rule_type: "invalid_type".into(),
            config: serde_json::json!({}),
            severity: "critical".into(),
            cooldown_secs: None,
        };
        let result = create_rule(State(state.clone()), Json(body)).await;
        assert!(result.is_err());

        // Invalid severity
        let body = CreateAlertRuleRequest {
            project_id: "proj".into(),
            name: "test".into(),
            service_id: "svc".into(),
            rule_type: "threshold".into(),
            config: serde_json::json!({}),
            severity: "urgent".into(),
            cooldown_secs: None,
        };
        let result = create_rule(State(state), Json(body)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn update_and_delete_rule() {
        let state = Arc::new(AppState::new());

        // Create
        let body = CreateAlertRuleRequest {
            project_id: "proj".into(),
            name: "Original".into(),
            service_id: "svc".into(),
            rule_type: "threshold".into(),
            config: serde_json::json!({}),
            severity: "warning".into(),
            cooldown_secs: None,
        };
        let created = create_rule(State(state.clone()), Json(body)).await.unwrap();
        let rule_id = created.0.data.id.clone();

        // Update
        let update_body = CreateAlertRuleRequest {
            project_id: "proj".into(),
            name: "Updated".into(),
            service_id: "svc".into(),
            rule_type: "threshold".into(),
            config: serde_json::json!({"changed": true}),
            severity: "critical".into(),
            cooldown_secs: Some(900),
        };
        let updated = update_rule(State(state.clone()), Path(rule_id.clone()), Json(update_body))
            .await
            .unwrap();
        assert_eq!(updated.0.data.name, "Updated");
        assert_eq!(updated.0.data.severity, "critical");

        // Delete
        let deleted = delete_rule(State(state.clone()), Path(rule_id.clone()))
            .await
            .unwrap();
        assert_eq!(deleted.0.data, "deleted");

        // Delete again → not found
        let result = delete_rule(State(state), Path(rule_id)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn list_events_with_filters() {
        let state = Arc::new(AppState::new());
        {
            let mut store = state.alert_event_store.write().await;
            store.add(AlertEventResponse {
                id: "evt_1".into(),
                rule_id: "r1".into(),
                rule_name: "Error Rate".into(),
                project_id: "proj".into(),
                service_id: "svc_api".into(),
                severity: "critical".into(),
                status: "firing".into(),
                message: "error_rate = 0.15".into(),
                metric_value: 0.15,
                threshold_value: 0.05,
                fired_at: "2026-03-14T12:00:00Z".into(),
                resolved_at: None,
            });
            store.add(AlertEventResponse {
                id: "evt_2".into(),
                rule_id: "r2".into(),
                rule_name: "Latency".into(),
                project_id: "proj".into(),
                service_id: "svc_api".into(),
                severity: "warning".into(),
                status: "resolved".into(),
                message: "latency spike resolved".into(),
                metric_value: 0.0,
                threshold_value: 500_000.0,
                fired_at: "2026-03-14T11:00:00Z".into(),
                resolved_at: Some("2026-03-14T11:30:00Z".into()),
            });
        }

        // All events
        let query = AlertEventsQuery {
            project_id: "proj".into(),
            status: None,
            severity: None,
            limit: None,
        };
        let result = list_events(State(state.clone()), Query(query)).await.unwrap();
        assert_eq!(result.0.data.len(), 2);

        // Only firing
        let query = AlertEventsQuery {
            project_id: "proj".into(),
            status: Some("firing".into()),
            severity: None,
            limit: None,
        };
        let result = list_events(State(state.clone()), Query(query)).await.unwrap();
        assert_eq!(result.0.data.len(), 1);
        assert_eq!(result.0.data[0].id, "evt_1");

        // Only critical
        let query = AlertEventsQuery {
            project_id: "proj".into(),
            status: None,
            severity: Some("critical".into()),
            limit: None,
        };
        let result = list_events(State(state), Query(query)).await.unwrap();
        assert_eq!(result.0.data.len(), 1);
    }
}
