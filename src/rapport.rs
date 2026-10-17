//! Rapport HTML autonome (un seul fichier, aucun accès réseau) ouvert dans le navigateur.

use std::fmt::Write;
use std::path::PathBuf;

use crate::machine::Audit;
use crate::reseau::Rapport;
use crate::risk::{Niveau, note};
use crate::{tr, trf, trp, trw, trwln};

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
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
    format!(
        "<span class=\"badge {}\">{}</span>",
        classe(n),
        n.map_or("OK", Niveau::libelle)
    )
}

fn carte_note(titre: &str, score: u32) -> String {
    let n = note(score);
    format!(
        "<div class=\"note n{n}\"><div class=\"lettre\">{n}</div><div><div class=\"etiq\">{titre}</div><div class=\"score\">{score}/100</div></div></div>"
    )
}

const CSS: &str = r"
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
";

/// Les 5 derniers tests de connexion, le plus récent en haut ; vide s'il n'y en a pas.
fn connexions(tests: &[crate::connexion::Resultat]) -> String {
    if tests.is_empty() {
        return String::new();
    }
    let mut h = String::from(tr!(
        "<h2>Connexion pour le jeu</h2><div class=carte><table><tr><td>Date</td><td>Ping</td><td>Gigue</td><td>Pertes</td><td>↓ Mbit/s</td><td>↑ Mbit/s</td><td>Bufferbloat</td></tr>",
        "<h2>Connection for gaming</h2><div class=carte><table><tr><td>Date</td><td>Ping</td><td>Jitter</td><td>Loss</td><td>↓ Mbit/s</td><td>↑ Mbit/s</td><td>Bufferbloat</td></tr>"
    ));
    let debit = |d: Option<f64>| d.map_or_else(|| "?".to_string(), |d| format!("{d:.0}"));
    for t in tests.iter().rev().take(5) {
        let bufferbloat = t.hausse_ms.map_or_else(
            || "?".to_string(),
            |m| format!("{} (+{m:.0} ms)", crate::connexion::note_bufferbloat(m).0),
        );
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{:.0} ms</td><td>{:.1} ms</td><td>{:.0} %</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&t.date),
            t.internet_ms,
            t.gigue_ms,
            t.pertes,
            debit(t.descendant),
            debit(t.montant),
            bufferbloat
        );
    }
    h += tr!(
        "</table><div class=meta>Menu c ou « sentinel connexion » pour un nouveau test.</div></div>",
        "</table><div class=meta>Menu c or “sentinel connexion” for a new test.</div></div>"
    );
    h
}

pub fn generer(audit: Option<&Audit>, reseau: Option<&Rapport>) -> std::io::Result<PathBuf> {
    let chemin = crate::reseau::dossier_donnees().join("rapport.html");
    std::fs::create_dir_all(chemin.parent().unwrap_or(&chemin))?;
    std::fs::write(&chemin, html(audit, reseau))?;
    // Version texte à côté : lisible sans navigateur ni affichage graphique (mode urgence).
    std::fs::write(chemin.with_extension("md"), markdown(audit, reseau))?;
    Ok(chemin)
}

/// Rapport en Markdown, sans couleur ni code : il se lit avec `cat`, un éditeur de texte ou sur un téléphone.
pub fn markdown(audit: Option<&Audit>, reseau: Option<&Rapport>) -> String {
    let mut m = String::new();
    let date = chrono::Local::now().format(tr!("%d/%m/%Y à %H:%M", "%Y-%m-%d %H:%M"));
    let _ = trwln!(
        m,
        "# Bilan de sécurité Sentinel\n\nGénéré le {date} par Sentinel {}.\n",
        "# Sentinel security check\n\nGenerated on {date} by Sentinel {}.\n",
        env!("CARGO_PKG_VERSION")
    );
    let ligne_note = |quoi: &str, score: u32| format!("- {quoi} : **{}** ({score}/100)\n", note(score));
    if let Some(a) = audit.filter(|a| a.fiable()) {
        m += &ligne_note(tr!("Cette machine", "This machine"), a.score);
    }
    if let Some(r) = reseau {
        m += &ligne_note(&trf!("Réseau {}", "Network {}", r.reseau), r.score_global);
    }
    if let Some(a) = audit {
        let _ = trwln!(m, "\n## Cette machine ({})\n", "\n## This machine ({})\n", a.systeme);
        // Les problèmes d'abord, les plus graves en tête ; puis ce qui va bien.
        let mut constats: Vec<_> = a.constats.iter().collect();
        constats.sort_by_key(|c| std::cmp::Reverse(c.probleme));
        for c in constats {
            let etiquette = c.probleme.map_or("OK", Niveau::libelle);
            let _ = writeln!(
                m,
                "- [{etiquette}] **{}** : {}",
                crate::langue::categorie(c.categorie),
                c.message
            );
            if let Some(k) = &c.correctif {
                let _ = trwln!(m, "  - À faire : {}", "  - To do: {}", k.action);
                for cmd in &k.commandes {
                    let _ = writeln!(m, "    `{cmd}`");
                }
            }
        }
    }
    if let Some(r) = reseau {
        let _ = trwln!(
            m,
            "\n## Réseau {}\n\n| Adresse | Appareil | Ports ouverts | Note |\n|---|---|---|---|",
            "\n## Network {}\n\n| Address | Device | Open ports | Grade |\n|---|---|---|---|",
            r.reseau
        );
        for h in &r.hotes {
            let ports = h
                .ports
                .iter()
                .map(|p| format!("{} {} ({})", p.libelle(), p.service, p.niveau.libelle()))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                m,
                "| {} | {} | {} | {} {} |",
                h.ip,
                h.titre().replace('|', "/"),
                if ports.is_empty() { "—".to_string() } else { ports },
                note(h.score),
                h.score
            );
        }
        let conseils: Vec<String> = r
            .hotes
            .iter()
            .flat_map(|h| h.alertes.iter().map(move |(_, a)| format!("- {} : {a}", h.ip)))
            .collect();
        if !conseils.is_empty() {
            let _ = trwln!(m, "\n### Conseils\n", "\n### Advice\n");
            m += &conseils.join("\n");
            m.push('\n');
        }
    }
    m
}

/// Encodage base64, pour mettre une image dans la page elle-même (le rapport reste un seul fichier).
fn base64(octets: &[u8]) -> String {
    const LETTRES: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(octets.len().div_ceil(3) * 4);
    for bloc in octets.chunks(3) {
        // 3 octets = 24 bits = 4 lettres de 6 bits ; « = » complète le dernier bloc.
        let n = bloc.iter().fold(0u32, |acc, &o| acc << 8 | u32::from(o)) << (8 * (3 - bloc.len()));
        for i in 0..4 {
            s.push(if i <= bloc.len() {
                char::from(LETTRES[(n >> (18 - 6 * i) & 63) as usize])
            } else {
                '='
            });
        }
    }
    s
}

fn html(audit: Option<&Audit>, reseau: Option<&Rapport>) -> String {
    let mut h = String::new();
    let date = chrono::Local::now().format(tr!("%d/%m/%Y à %H:%M", "%Y-%m-%d %H:%M"));
    // Le logo dans l'onglet du navigateur (32 px, environ 3 Ko).
    let logo = base64(include_bytes!("../assets/icones/sentinel-32.png"));
    let _ = trw!(
        h,
        "<!doctype html><html lang=fr><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>Rapport Sentinel</title><link rel=icon href=\"data:image/png;base64,{logo}\"><style>{CSS}</style></head><body><main><h1>Bilan de sécurité</h1><p class=sous>Généré par Sentinel le {date}</p><div class=notes>",
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>Sentinel report</title><link rel=icon href=\"data:image/png;base64,{logo}\"><style>{CSS}</style></head><body><main><h1>Security check</h1><p class=sous>Generated by Sentinel on {date}</p><div class=notes>"
    );
    // Une note de machine n'est montrée que si l'audit a vraiment pu se faire.
    let audit_note = audit.filter(|a| a.fiable());
    if let Some(a) = audit_note {
        h += &carte_note(tr!("Cette machine", "This machine"), a.score);
    }
    if let Some(r) = reseau {
        h += &carte_note(&trf!("Réseau {}", "Network {}", esc(&r.reseau)), r.score_global);
    }
    if let (Some(a), Some(r)) = (audit_note, reseau) {
        h += &carte_note("Global", a.score.min(r.score_global));
    }
    h += "</div>";
    if let Some(svg) = crate::historique::courbe(&crate::historique::charger()) {
        let _ = trw!(
            h,
            "<h2>Évolution des notes</h2><div class=carte>{svg}<div class=meta><span style=\"color:var(--info)\">●</span> cette machine · <span style=\"color:var(--ok)\">●</span> réseau (30 derniers bilans complets)</div></div>",
            "<h2>Grade history</h2><div class=carte>{svg}<div class=meta><span style=\"color:var(--info)\">●</span> this machine · <span style=\"color:var(--ok)\">●</span> network (last 30 full checks)</div></div>"
        );
    }

    h += &connexions(&crate::connexion::historique());

    if let Some(a) = audit {
        h += tr!(
            "<h2>Cette machine</h2><div class=carte>",
            "<h2>This machine</h2><div class=carte>"
        );
        for c in &a.constats {
            let _ = write!(
                h,
                "<div class=ligne>{}<div><span class=cat>{}</span> {}",
                badge(c.probleme),
                esc(crate::langue::categorie(c.categorie)),
                esc(&c.message)
            );
            if let Some(k) = &c.correctif {
                let icone = if k.automatique {
                    tr!(
                        "🔧 Correction automatique (sentinel → Corriger)",
                        "🔧 Automatic fix (sentinel → Fix)"
                    )
                } else {
                    tr!("💡 À faire", "💡 To do")
                };
                let _ = trw!(
                    h,
                    "<div class=fix>{icone} : {}",
                    "<div class=fix>{icone}: {}",
                    esc(&k.action)
                );
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
        let nom = r
            .nom_reseau
            .as_deref()
            .map(|n| trf!(" « {} »", " “{}”", esc(n)))
            .unwrap_or_default();
        let _ = trw!(
            h,
            "<h2>Réseau{nom} — {} appareils</h2>",
            "<h2>Network{nom} — {} devices</h2>",
            r.hotes.len()
        );
        for hote in &r.hotes {
            let role = hote
                .role
                .map(|r| format!(" · {}", crate::langue::role(r)))
                .unwrap_or_default();
            let neuf = if hote.nouvelle {
                tr!(
                    " <span class=neuf>NOUVEL APPAREIL</span>",
                    " <span class=neuf>NEW DEVICE</span>"
                )
            } else {
                ""
            };
            let depuis = match (&hote.premier_vu, hote.nouvelle) {
                (Some(d), false) => trf!(" · connu depuis le {}", " · known since {}", crate::reseau::date_fr(d)),
                _ => String::new(),
            };
            let _ = trw!(
                h,
                "<div class=\"carte hote\"><h3>{} <span class=meta>{}{}</span>{neuf}</h3><div class=meta>{}{depuis} · score {}/100</div>",
                "<div class=\"carte hote\"><h3>{} <span class=meta>{}{}</span>{neuf}</h3><div class=meta>{}{depuis} · score {}/100</div>",
                hote.ip,
                esc(&hote.titre()),
                esc(&role),
                esc(hote.mac.as_deref().unwrap_or(tr!("MAC inconnue", "unknown MAC"))),
                hote.score
            );
            if hote.ports.is_empty() {
                h += tr!(
                    "<div class=meta>Aucun port ouvert parmi ceux testés.</div>",
                    "<div class=meta>No open port among those tested.</div>"
                );
            } else {
                h += "<table>";
                for p in &hote.ports {
                    let ban = p
                        .banniere
                        .as_deref()
                        .map(|b| format!("<div class=ban>{}</div>", esc(b)))
                        .unwrap_or_default();
                    let ban = ban
                        + &p.programme
                            .as_deref()
                            .map(|n| {
                                trf!(
                                    "<div class=ban>programme : {}</div>",
                                    "<div class=ban>program: {}</div>",
                                    esc(n)
                                )
                            })
                            .unwrap_or_default();
                    let _ = write!(
                        h,
                        "<tr><td>{}</td><td>{}{ban}</td><td>{}</td></tr>",
                        p.libelle(),
                        esc(p.service),
                        badge(Some(p.niveau))
                    );
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
        h += tr!(
            "<h2>Déjà vus, absents aujourd'hui</h2><div class=carte><ul>",
            "<h2>Seen before, absent today</h2><div class=carte><ul>"
        );
        for a in &r.absents {
            let quand = a
                .dernier_vu
                .as_deref()
                .map(|d| trf!(" — vu le {}", " — seen on {}", crate::reseau::date_fr(d)))
                .unwrap_or_default();
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
            trp!("  Rapport : {}", "  Report: {}", p.display());
            crate::machine::ouvrir(&p.display().to_string());
        }
        Err(e) => trp!(
            "  Impossible d'écrire le rapport : {e}",
            "  Could not write the report: {e}"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rapport_texte() {
        use crate::machine::{Audit, Constat};
        let audit = Audit {
            systeme: "Linux",
            score: 85,
            constats: vec![
                Constat {
                    categorie: "Pare-feu",
                    probleme: None,
                    message: "ufw actif.".into(),
                    correctif: None,
                    verifie: true,
                },
                Constat {
                    categorie: "Ports en écoute",
                    probleme: Some(Niveau::Eleve),
                    message: "445/tcp ouvert.".into(),
                    correctif: None,
                    verifie: true,
                },
            ],
        };
        let m = markdown(Some(&audit), None);
        assert!(m.starts_with("# Bilan de sécurité Sentinel"));
        assert!(m.contains("**B** (85/100)"));
        // Le problème passe avant ce qui va bien.
        assert!(m.find("445/tcp").unwrap() < m.find("ufw actif").unwrap());
        assert!(!m.contains('\x1b'));
    }

    #[test]
    fn tests_de_connexion_dans_le_rapport() {
        assert_eq!(connexions(&[]), "");
        let r = crate::connexion::Resultat {
            date: "2026-10-17 15:00".into(),
            internet_ms: 17.2,
            gigue_ms: 3.4,
            pertes: 0.0,
            descendant: Some(106.4),
            montant: None,
            hausse_ms: Some(43.0),
        };
        let h = connexions(&[r]);
        assert!(h.contains("<td>17 ms</td>") && h.contains("<td>106</td><td>?</td>") && h.contains("B (+43 ms)"));
    }

    #[test]
    fn logo_dans_l_onglet() {
        // Exemples de la norme (RFC 4648).
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        // « iVBORw0KGgo » : la signature d'un fichier PNG, encodée.
        assert!(html(None, None).contains("<link rel=icon href=\"data:image/png;base64,iVBORw0KGgo"));
    }
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
            udp: false,
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
            upnp: None,
        };
        let page = html(None, Some(&r));
        assert!(!page.contains("<script>alert"));
        assert!(!page.contains("<img src=x"));
        assert!(!page.contains("<b>x</b>") && !page.contains("<i>wifi</i>"));
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }
}
