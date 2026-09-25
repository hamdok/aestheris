# Aestheris Gateway

[English](README.md) · **Français**

La passerelle de confiance entre les agents IA et vos API. **Un agent utilise une vraie clé API sans
jamais la voir, et chaque action est vérifiée puis consignée.**

```text
┌ bac à sable ─┐
│    agent     │──(jeton fantôme)──▶ passerelle 127.0.0.1 ──(vraie clé)──▶ api.stripe.com
└──────────────┘                     │ jeton de session · politique · détection de secrets
  ~/.aws, .env, coffre : illisibles  │ proxy de sortie (liste blanche) · journal chaîné
```

- [Conception](docs/DESIGN.md) (en anglais) : architecture, trajet d'une requête, modèle de
  menaces, limites.
- [NOTICE](NOTICE) : code et données repris d'autres projets, et leurs licences.

## Démo en 2 minutes (sans aucun compte externe)

```bash
./examples/demo.sh
```

Elle crée un coffre chiffré, y range une clé Stripe factice, lance un « agent » derrière la passerelle,
puis montre que :

1. l'agent ne voit qu'un jeton `aes_ph_…` ;
2. la fausse API Stripe reçoit la vraie clé ;
3. la suppression d'un client est refusée par la politique ;
4. une clé AWS collée par erreur est bloquée avant de sortir ;
5. le journal est intact (`aestheris audit verify`) ;
6. sur macOS, le même agent lancé dans le bac à sable ne peut lire ni le coffre ni le `.env`, ne voit
   plus la variable `AWS_SECRET_ACCESS_KEY` du terminal, ne peut ni joindre un serveur externe, ni
   piloter une autre application, ni poser un hook Git, ni écrire hors de son dossier, mais utilise
   toujours l'API Stripe par la passerelle ;
7. un remboursement attend l'accord d'un humain (`aestheris approve`) : le premier est accepté, le
   second refusé, et le journal indique qui a décidé ;
8. données fantômes : le modèle ne voit que `[CLIENT_1]` et `[EMAIL_1]`, le CRM reçoit la vraie
   adresse, et l'agent détourné qui l'envoie à un serveur externe n'envoie que `[EMAIL_1]` ; le
   disjoncteur saute et suspend la session ;
9. premier déploiement en mode observation : rien n'est bloqué, et le rapport chiffre ce que les
   agents ont réellement envoyé (adresses, téléphones, secrets) ;
10. `aestheris scan` sur un projet « vibe codé » : clé Stripe dans une variable `NEXT_PUBLIC_`,
    clé AWS dans un fichier suivi par git, `.env.local` que git n'ignore pas, clé OpenAI lisible
    par les agents.

## Démarrage rapide

L'interface parle français si la langue du système est le français, anglais sinon
(`AESTHERIS_LANG=fr` ou `en` pour choisir).

```bash
cargo install --path .                        # installe la commande aestheris
cd mon-projet
aestheris scan                                # 5 secondes, sans coffre : ce que vos agents peuvent lire ou publier
aestheris init                                # agent, services, clés → coffre + aestheris.yaml
aestheris run -- claude                       # l'agent travaille derrière la passerelle
aestheris approve                             # dans un autre terminal : valider les actions sensibles
```

`aestheris init` pose deux questions (quel agent, quels services parmi Anthropic, OpenAI, GitHub,
Stripe), crée le coffre, y range les clés (en important celles déjà présentes dans le terminal, que
vous pouvez ensuite retirer) et écrit une politique commentée, prête à relire et à versionner. Sans
terminal (CI, scripts) : `aestheris init --agent claude-code --service github`.

`aestheris scan` ne demande rien : il signale les secrets publiés ou publiables (variables
`NEXT_PUBLIC_`/`VITE_`…, fichiers suivis par git, `.env` que git n'ignore pas, clé `service_role`
de Supabase), les secrets lisibles par les agents, les jetons en clair dans les configurations MCP
(Claude, Cursor, VS Code, Windsurf, Gemini, Codex) et les réglages d'agent sans garde-fou. Aucune
valeur n'est affichée. Code de retour 1 si un constat est critique : en CI ou en crochet
pre-commit, `aestheris scan --no-home` (`--json` pour les outils, `--exclude 'tests/**'`, ou
`aestheris:allow` en fin de ligne).

Le modèle « Claude Code » a été réglé sur le vrai Claude Code, lancé dans le bac à sable : jeton de
passerelle dans `ANTHROPIC_AUTH_TOKEN`, écriture dans `~/.claude`, trafic non essentiel coupé.

## Utilisation détaillée

```bash
cargo build --release
alias aestheris=./target/release/aestheris

aestheris vault init                          # mot de passe maître (Argon2id)
aestheris vault set anthropic/api             # saisie masquée, stockée chiffrée
aestheris policy check examples/aestheris.yaml
aestheris run --policy examples/aestheris.yaml -- claude
aestheris approve                             # dans un autre terminal : valider les actions « ask »
aestheris audit show
aestheris audit verify
```

`aestheris serve` démarre la passerelle seule et affiche les variables à exporter pour un agent
lancé ailleurs.

## Ce que fait la passerelle

| Brique | Détail |
|---|---|
| Coffre | Argon2id (64 Mio, 3 passes) → clé de chiffrement de clé → clé de données (enveloppe) → secrets en XChaCha20-Poly1305, nom du secret en données associées, fichier 0600 |
| Jeton fantôme | 256 bits aléatoires par session, comparé en temps constant ; sans lui, la clé n'est jamais injectée |
| Politique | YAML versionné ; règles par méthode et chemin, première qui correspond, refus par défaut |
| Détection | Nos 12 motifs (AWS, GitHub, OpenAI, Anthropic, Stripe, Slack, Google, Supabase, clés privées, URL de bases, JWT) + ~220 règles au format gitleaks (Hugging Face, GitLab, npm, SendGrid, Twilio…) avec mots-clés, entropie et exceptions |
| Réseau | Écoute sur 127.0.0.1 uniquement ; amont en HTTPS ; métadonnées cloud toujours interdites ; aucune redirection suivie |
| Journal | NDJSON chaîné SHA-256, vérifiable ; types de secrets, jamais leurs valeurs |
| Bac à sable Linux (v0.5) | bubblewrap + seccomp : disque en lecture seule sauf le dossier de travail, secrets masqués, `/tmp` neuf, espace réseau vide avec relais vers la passerelle, ni socket Unix, ni injection de frappes. Testé sur Ubuntu 24.04 |
| Bac à sable (macOS) | Seatbelt « tout interdit sauf le nécessaire » : secrets illisibles ; écriture limitée au dossier de travail ; ni `open`, ni AppleScript, ni sockets Unix, ni autres services locaux ; `.zshrc`, hooks Git, `.vscode`, configurations MCP non modifiables |
| Environnement (v0.2) | Variables portant un secret retirées avant le lancement de l'agent |
| Sortie réseau | Proxy CONNECT authentifié : liste blanche d'hôtes et de ports ; adresses internes, de métadonnées cloud et du poste lui-même refusées après résolution DNS ; connexion à l'adresse vérifiée ; DNS fermé dans le bac à sable |
| Processus de la passerelle | Aucun débogueur ni core dump ; refus de démarrer si une bibliothèque a pu être injectée |
| Analyse de projet (v0.11) | `aestheris scan` : secrets publiés, publiables ou lisibles par les agents, jetons en clair dans les configurations MCP, réglages d'agent sans garde-fou, emplacements de secrets du dossier personnel ; valeurs d'exemple écartées (clés `…EXAMPLE`, `user:pass@`, clé `anon` de Supabase) ; aucune valeur affichée ; code 1 si critique (CI, pre-commit) |
| Observation et rapport (v0.10) | `mode: observe` (ou `aestheris init --observe`) : rien n'est bloqué ni modifié, tout ce qui l'aurait été est noté ; `aestheris audit report` : bilan pour la direction, dont les données sensibles réellement envoyées aux fournisseurs d'IA |
| Provenance et disjoncteur (v0.9) | Sources de données (`phantom: true`) : réponses pseudonymisées avant l'agent, provenance respectée ; disjoncteur (`guard`) : au-delà de seuils de signes d'un agent détourné, validation humaine ou session suspendue |
| Données fantômes (v0.8) | `privacy.release` : chaque catégorie de données ne redevient réelle que là où la politique le permet (écran, actions de l'agent, services précis) ; un agent détourné par une injection de prompt n'exfiltre que des pseudonymes |
| Confidentialité (v0.7) | Bouclier : le fournisseur d'IA ne reçoit que des pseudonymes (`[EMAIL_1]`, `[CLIENT_2]`, identité du poste…), rétablis sur la machine, même en flux et dans les appels d'outils ; métadonnées identifiantes retirées ; `aestheris audit exposure` |
| Démarrage (v0.6) | `aestheris init` : politiques prêtes à l'emploi (Claude Code ou agent générique ; Anthropic, OpenAI, GitHub, Stripe), clés importées dans le coffre ; `agent.env` pour des variables non secrètes (les valeurs qui ressemblent à un secret sont refusées) |
| Validation humaine (v0.4) | Règle `action: ask` (et hôtes inconnus en sortie) : la requête attend l'accord d'un humain via `aestheris approve` ; une fois ou pour la session ; sans réponse → refus ; l'agent et ses sous-processus ne peuvent pas répondre ; décision et auteur au journal |

## Tests

```bash
cargo test                                  # tests unitaires, bout en bout, évasions réelles du bac à sable (macOS et Linux)
cargo clippy --all-targets -- -D warnings
```

Sous Linux, le bac à sable demande bubblewrap (`apt install bubblewrap`). Sur Ubuntu 23.10 et
suivantes, autorisez-le une fois (profil AppArmor limité à bubblewrap) :

```bash
sudo install -m 644 packaging/apparmor/bwrap /etc/apparmor.d/bwrap
sudo apparmor_parser -r /etc/apparmor.d/bwrap
```

Pour tester la version Linux depuis un Mac : une machine virtuelle [Lima](https://lima-vm.io)
(`limactl start template:ubuntu-24.04`), puis `cargo test` dedans, avec `CARGO_TARGET_DIR` hors du
dossier monté.

## Limites connues (prochaines étapes)

- L'agent doit respecter la variable d'URL de base (c'est le cas de Claude Code, des SDK OpenAI,
  Anthropic, Stripe…). Pour les autres : interception TLS prévue.
- Bac à sable macOS et Linux ; Windows plus tard. Sous Linux, les protections par motif (`.env`,
  hooks Git…) ne couvrent que les fichiers présents au lancement.
- Les tunnels du proxy de sortie sont opaques : hôte et port contrôlés, contenu non inspecté
  (interception TLS prévue).
- Dans le bac à sable, `git init`, `git clone` et `git remote` exigent `allow_git_config: true`.
- Si l'agent peut écrire dans sa propre configuration (`~/.claude.json`), il peut y ajouter un
  serveur MCP, lancé hors bac à sable si l'agent est ensuite démarré sans Aestheris.
- Validation humaine : terminal local seulement (`aestheris approve`) ; Slack, Teams et console web
  ensuite. Sans bac à sable, elle protège des erreurs de l'agent, pas d'un agent malveillant.
- Contrôle des commandes shell et des outils MCP : à venir.
- `AESTHERIS_PASSWORD` sert aux démos et à la CI ; en usage normal, le mot de passe est saisi de façon
  masquée. Le trousseau du système remplacera la saisie en v1.
