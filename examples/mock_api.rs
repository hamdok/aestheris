//! Fausse API pour la démo : écoute sur 127.0.0.1:4099 et affiche, pour chaque requête reçue,
//! la méthode, le chemin, la clé qui lui est parvenue et le contenu. Elle joue api.stripe.com,
//! un CRM, un serveur pirate, et, sur `/v1/messages`, un modèle d'IA (format d'Anthropic) qui
//! reprend dans sa réponse les éléments qu'il a reçus.
//!
//!     cargo run --example mock_api

use axum::Router;
use axum::extract::Request;

#[tokio::main]
async fn main() {
    async fn show(req: Request) -> axum::Json<serde_json::Value> {
        let auth = req
            .headers()
            .get("authorization")
            .or_else(|| req.headers().get("x-api-key"))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("(aucune)")
            .to_string();
        let (method, path) = (req.method().clone(), req.uri().path().to_string());
        let body = axum::body::to_bytes(req.into_body(), 1 << 20)
            .await
            .unwrap_or_default();
        let body = String::from_utf8_lossy(&body).to_string();
        if path.ends_with("/v1/messages") {
            // Faux modèle : il ne voit que ce que la passerelle lui transmet.
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let asked = v["messages"][0]["content"]
                .as_str()
                .unwrap_or("")
                .to_string();
            println!("[faux modèle] message reçu : « {asked} »");
            let re = regex::Regex::new(r"\[[A-Z]+_\d+\]").expect("motif");
            let tokens: Vec<&str> = re.find_iter(&asked).map(|m| m.as_str()).collect();
            let email = tokens
                .iter()
                .find(|t| t.starts_with("[EMAIL"))
                .copied()
                .unwrap_or("");
            return axum::Json(serde_json::json!({ "content": [
                { "type": "text", "text": format!("Je range la fiche de {} dans le CRM.", tokens.join(" ")) },
                { "type": "tool_use", "id": "t1", "name": "enregistrer", "input": { "email": email } }
            ]}));
        }
        let shown = if body.is_empty() {
            String::new()
        } else {
            format!(" · contenu : {body}")
        };
        println!("[fausse API] {method} {path}  ← clé reçue : {auth}{shown}");
        axum::Json(
            serde_json::json!({ "id": "ch_demo_123", "status": "succeeded", "amount": 2000 }),
        )
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:4099")
        .await
        .expect("port 4099 libre");
    println!("[fausse API] prête sur http://127.0.0.1:4099");
    axum::serve(listener, Router::new().fallback(show))
        .await
        .expect("serveur");
}
