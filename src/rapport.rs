//! Rapport HTML autonome (un seul fichier, aucun accès réseau) ouvert dans le navigateur.

use std::fmt::Write;
use std::path::PathBuf;

use crate::machine::Audit;
use crate::reseau::Rapport;
use crate::risk::{Niveau, note};

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn classe(n: Option<Niveau>) -> &'static str {
    match n {
        None => "ok",
        Some(Niveau::Info) => "info",
        Some(Niveau::Moyen) => "moyen",
        Some(Niveau::Eleve) => "eleve",
        Some(Niveau::Critique) => "critique",
    }
}

fn badge(n: Option<Niveau>) -> String {
    format!("<span class=\"badge {}\">{}</span>", classe(n), n.map_or("OK", Niveau::libelle))
}

fn carte_note(titre: &str, score: u32) -> String {
    let n = note(score);
    format!("<div class=\"note n{n}\"><div class=\"lettre\">{n}</div><div><div class=\"etiq\">{titre}</div><div class=\"score\">{score}/100</div></div></div>")
}

const CSS: &str = r#"
:root{--bg:#f6f6f4;--carte:#fff;--texte:#1b1b1b;--doux:#666;--bord:#e2e2de;
--ok:#1f8a4c;--info:#2a7bb5;--moyen:#b58900;--eleve:#d0611b;--critique:#c62828;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#000;--carte:#0d0d0d;--texte:#ececec;--doux:#9a9a9a;--bord:#222;
--ok:#4cc27a;--info:#5aa9e6;--moyen:#e2b93b;--eleve:#f08a4b;--critique:#ff5a5a;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--texte);font:15px/1.5 system-ui,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 12px}
.sous{color:var(--doux);margin:0 0 20px}.notes{display:flex;gap:12px;flex-wrap:wrap}
.note{display:flex;gap:14px;align-items:center;background:var(--carte);border:1px solid var(--bord);border-radius:12px;padding:14px 18px;flex:1;min-width:200px}
.lettre{font-size:38px;font-weight:800;width:52px;text-align:center}.nA .lettre,.nB .lettre{color:var(--ok)}.nC .lettre{color:var(--moyen)}.nD .lettre,.nF .lettre{color:var(--critique)}
.etiq{color:var(--doux);font-size:13px}.score{font-weight:600}
.carte{background:var(--carte);border:1px solid var(--bord);border-radius:12px;padding:14px 18px;margin:10px 0}
.ligne{display:flex;gap:10px;align-items:baseline;padding:6px 0;border-top:1px solid var(--bord)}.ligne:first-child{border-top:0}
.cat{font-weight:600;min-width:130px}.badge{font-size:11px;font-weight:700;padding:2px 7px;border-radius:6px;color:#fff;white-space:nowrap}
.ok{background:var(--ok)}.info{background:var(--info)}.moyen{background:var(--moyen)}.eleve{background:var(--eleve)}.critique{background:var(--critique)}
.fix{color:var(--doux);font-size:13px;margin-top:2px}code{font:12px ui-monospace,monospace;background:var(--bg);padding:1px 5px;border-radius:4px;word-break:break-all}
.hote h3{margin:0;font-size:16px}.meta{color:var(--doux);font-size:13px}.neuf{color:var(--moyen);font-weight:700}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:14px}td{padding:4px 6px;border-top:1px solid var(--bord);vertical-align:top}
.ban{color:var(--doux);font-size:12px}ul{margin:8px 0 0;padding-left:20px}
@media (max-width:600px){.ligne{flex-wrap:wrap}.cat{min-width:0}}
"#;

pub fn generer(audit: Option<&Audit>, reseau: Option<&Rapport>) -> std::io::Result<PathBuf> {
    let chemin = crate::reseau::dossier_donnees().join("rapport.html");
    std::fs::create_dir_all(chemin.parent().unwrap_or(&chemin))?;
    std::fs::write(&chemin, html(audit, reseau))?;
    Ok(chemin)
}

fn html(audit: Option<&Audit>, reseau: Option<&Rapport>) -> String {
    let mut h = String::new();
    let date = chrono::Local::now().format("%d/%m/%Y à %H:%M");
    let _ = write!(
        h,
        "<!doctype html><html lang=fr><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>Rapport netscan</title><style>{CSS}</style></head><body><main><h1>Bilan de sécurité</h1><p class=sous>Généré par netscan le {date}</p><div class=notes>"
    );
    // Une note de machine n'est montrée que si l'audit a vraiment pu se faire.
    let audit_note = audit.filter(|a| a.fiable());
    if let Some(a) = audit_note {
        h += &carte_note("Cette machine", a.score);
    }
    if let Some(r) = reseau {
        h += &carte_note(&format!("Réseau {}", esc(&r.reseau)), r.score_global);
    }
    if let (Some(a), Some(r)) = (audit_note, reseau) {
        h += &carte_note("Global", a.score.min(r.score_global));
    }
    h += "</div>";

    if let Some(a) = audit {
        h += "<h2>Cette machine</h2><div class=carte>";
        for c in &a.constats {
            let _ = write!(h, "<div class=ligne>{}<div><span class=cat>{}</span> {}", badge(c.probleme), esc(c.categorie), esc(&c.message));
            if let Some(k) = &c.correctif {
                let icone = if k.automatique { "🔧 Correction automatique (netscan → Corriger)" } else { "💡 À faire" };
                let _ = write!(h, "<div class=fix>{icone} : {}", esc(&k.action));
                for cmd in &k.commandes {
                    let _ = write!(h, "<br><code>{}</code>", esc(cmd));
                }
                h += "</div>";
            }
            h += "</div></div>";
        }
        h += "</div>";
    }

    if let Some(r) = reseau {
        let nom = r.nom_reseau.as_deref().map(|n| format!(" « {} »", esc(n))).unwrap_or_default();
        let _ = write!(h, "<h2>Réseau{nom} — {} appareils</h2>", r.hotes.len());
        for hote in &r.hotes {
            let role = hote.role.map(|r| format!(" · {r}")).unwrap_or_default();
            let neuf = if hote.nouvelle { " <span class=neuf>NOUVEL APPAREIL</span>" } else { "" };
            let depuis = match (&hote.premier_vu, hote.nouvelle) {
                (Some(d), false) => format!(" · connu depuis le {}", crate::reseau::date_fr(d)),
                _ => String::new(),
            };
            let _ = write!(
                h,
                "<div class=\"carte hote\"><h3>{} <span class=meta>{}{}</span>{neuf}</h3><div class=meta>{}{depuis} · score {}/100</div>",
                hote.ip,
                esc(&hote.titre()),
                esc(&role),
                esc(hote.mac.as_deref().unwrap_or("MAC inconnue")),
                hote.score
            );
            if hote.ports.is_empty() {
                h += "<div class=meta>Aucun port ouvert parmi ceux testés.</div>";
            } else {
                h += "<table>";
                for p in &hote.ports {
                    let ban = p.banniere.as_deref().map(|b| format!("<div class=ban>{}</div>", esc(b))).unwrap_or_default();
                    let ban = ban + &p.programme.as_deref().map(|n| format!("<div class=ban>programme : {}</div>", esc(n))).unwrap_or_default();
                    let _ = write!(h, "<tr><td>{}/tcp</td><td>{}{ban}</td><td>{}</td></tr>", p.port, esc(p.service), badge(Some(p.niveau)));
                }
                h += "</table>";
            }
            if !hote.alertes.is_empty() {
                h += "<ul>";
                for (n, msg) in &hote.alertes {
                    let _ = write!(h, "<li>{} {}</li>", badge(Some(*n)), esc(msg));
                }
                h += "</ul>";
            }
            h += "</div>";
        }
    }
    if let Some(r) = reseau.filter(|r| !r.absents.is_empty()) {
        h += "<h2>Déjà vus, absents aujourd'hui</h2><div class=carte><ul>";
        for a in &r.absents {
            let quand = a.dernier_vu.as_deref().map(|d| format!(" — vu le {}", crate::reseau::date_fr(d))).unwrap_or_default();
            let _ = write!(h, "<li>{} {}{}</li>", a.ip, esc(&a.titre), quand);
        }
        h += "</ul></div>";
    }
    h += "</main></body></html>";
    h
}

pub fn ouvrir(audit: Option<&Audit>, reseau: Option<&Rapport>) {
    match generer(audit, reseau) {
        Ok(p) => {
            println!("  Rapport : {}", p.display());
            crate::machine::ouvrir(&p.display().to_string());
        }
        Err(e) => println!("  Impossible d'écrire le rapport : {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reseau::{Hote, PortOuvert};

    #[test]
    fn une_banniere_piegee_ne_devient_pas_du_code() {
        // Un appareil du réseau choisit sa bannière : elle ne doit jamais s'exécuter dans le rapport.
        let p = PortOuvert {
            port: 8080,
            service: "HTTP alt",
            niveau: Niveau::Moyen,
            banniere: Some("<script>alert(1)</script>".into()),
            conseil: "",
            nouveau: false,
            programme: Some("<b>x</b>".into()),
        };
        let h = Hote {
            ip: "10.0.0.9".parse().unwrap(),
            nom: Some("<img src=x onerror=alert(2)>".into()),
            mac: None,
            fabricant: None,
            surnom: None,
            premier_vu: None,
            role: None,
            nouvelle: false,
            ports: vec![p],
            alertes: vec![],
            score: 95,
        };
        let r = Rapport {
            reseau: "10.0.0.0/24".into(),
            nom_reseau: Some("<i>wifi</i>".into()),
            absents: vec![],
            duree_s: 1.0,
            score_global: 95,
            note: "A",
            hotes: vec![h],
        };
        let page = html(None, Some(&r));
        assert!(!page.contains("<script>alert"));
        assert!(!page.contains("<img src=x"));
        assert!(!page.contains("<b>x</b>") && !page.contains("<i>wifi</i>"));
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }
}
