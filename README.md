# RMW-PenStrike

**Outil autonome de test d'intrusion boîte noire (black-box pentest), piloté par des agents LLM, avec anonymisation locale des données sensibles et génération automatique de rapport professionnel (PDF + Word).**

```
██████╗ ███╗   ███╗██╗    ██╗      ██████╗ ███████╗███╗   ██╗
██╔══██╗████╗ ████║██║    ██║      ██╔══██╗██╔════╝████╗  ██║
██████╔╝██╔████╔██║██║ █╗ ██║█████╗██████╔╝█████╗  ██╔██╗ ██║
██╔══██╗██║╚██╔╝██║██║███╗██║╚════╝██╔═══╝ ██╔══╝  ██║╚██╗██║
██║  ██║██║ ╚═╝ ██║╚███╔███╔╝      ██║     ███████╗██║ ╚████║
╚═╝  ╚═╝╚═╝     ╚═╝ ╚══╝╚══╝       ╚═╝     ╚══════╝╚═╝  ╚═══╝
                     S T R I K E
```

## Sommaire

- [Présentation](#présentation)
- [Pourquoi RMW-PenStrike](#pourquoi-rmw-penstrike)
- [Architecture du pipeline](#architecture-du-pipeline)
- [Installation](#installation)
- [Désinstallation](#désinstallation)
- [Utilisation](#utilisation)
- [Options de la ligne de commande](#options-de-la-ligne-de-commande)
- [Fichiers de configuration](#fichiers-de-configuration)
- [Anonymisation des données sensibles](#anonymisation-des-données-sensibles)
- [Génération du rapport](#génération-du-rapport)
- [Exemples d'utilisation](#exemples-dutilisation)
- [Avertissement légal](#avertissement-légal)

---

## Présentation

`rmwpen` (**RMW-PenStrike**) est un outil en ligne de commande (CLI) destiné aux professionnels de la cybersécurité. Il automatise et orchestre l'ensemble du cycle d'un test d'intrusion **boîte noire** : de la reconnaissance initiale jusqu'à la production d'un rapport final structuré, en passant par l'énumération et l'exploitation des vulnérabilités.

L'outil repose sur des **agents pilotés par des modèles de langage (LLM)** qui :

1. analysent le périmètre de test fourni,
2. planifient et exécutent les commandes de sécurité appropriées (nmap, gobuster, whatweb, curl, etc.),
3. interprètent les résultats et adaptent leur stratégie,
4. documentent chaque piste explorée,
5. produisent à la fin un **rapport de pentest professionnel** (PDF et Word), conforme aux standards de l'industrie (OWASP Testing Guide, CVSS, CWE).

L'expert humain conserve à tout moment un rôle de supervision : l'outil ne dépasse jamais le périmètre défini, et toutes les actions sont journalisées.

## Pourquoi RMW-PenStrike

Les agents IA "classiques" utilisés en pentest présentent plusieurs limites :

- ils travaillent **séquentiellement**, sans explorer plusieurs pistes en parallèle ;
- ils s'appuient sur un **seul LLM**, ce qui limite la couverture de détection ;
- ils envoient les résultats de commandes **en clair sur Internet**, exposant potentiellement des données sensibles (mots de passe, tokens, informations personnelles).

RMW-PenStrike répond à ces limites avec quatre mécanismes clés :

| Limite des outils classiques | Réponse de RMW-PenStrike |
|---|---|
| Exploration séquentielle | Plusieurs **contextes d'investigation en parallèle**, pouvant partager des informations entre eux |
| Dépendance à un seul LLM | Support de **plusieurs moteurs LLM** (Gemini, Codex, API, bascule automatique) |
| Données sensibles envoyées en clair | **Anonymisation locale** systématique avant tout envoi à un LLM externe |
| Pas de livrable structuré | **Génération automatique** d'un rapport professionnel PDF + Word en fin d'engagement |

L'outil s'exécute directement sur la machine de l'utilisateur (CLI natif), ce qui lui permet de s'appuyer sur les outils de sécurité déjà installés (Kali Linux ou environnement équivalent).

## Architecture du pipeline

```
[CIBLE + PÉRIMÈTRE]
        │
        ▼
  RECONNAISSANCE  ──▶  ÉNUMÉRATION  ──▶  EXPLOITATION
        │ (agents LLM en contextes parallèles, données anonymisées)
        ▼
[CONTEXTES BRUTS : files/context_*.txt]
        │
        ▼
   GÉNÉRATION DU RAPPORT (Markdown structuré via LLM)
        ▼
   ENRICHISSEMENT (corrélation CVE / exploits publics)
        ▼
   MAPPING (réinjection des vraies valeurs anonymisées)
        ▼
   MISE EN FORME FINALE (PDF + DOCX)
        ▼
[RAPPORT_PENTEST.pdf]  [RAPPORT_PENTEST.docx]  [files.zip]
```

Chaque commande exécutée par les agents passe par un cycle complet de protection :

1. le LLM raisonne et émet une commande contenant uniquement des **tokens anonymisés** (`<IP_001>`, `<URL_002>`, etc.) ;
2. la commande est **désanonymisée localement** juste avant exécution (les vraies valeurs ne quittent jamais la machine) ;
3. la commande passe un **contrôle de sécurité** (blocage des chemins systèmes critiques, des commandes d'élévation de privilèges, etc.) avant d'être exécutée dans un répertoire de travail isolé ;
4. le résultat est **réanonymisé** avant d'être renvoyé au LLM.

## Installation

L'outil est livré avec un script d'installation qui le déploie comme une véritable commande système, au même titre que `nmap` ou `gobuster`.

```bash
sudo ./install.sh
```

Ce script effectue automatiquement :

1. la vérification des droits administrateur ;
2. l'installation des paquets système requis (`python3`, `python3-venv`, `python3-pip`) ;
3. la copie des fichiers du projet vers `/opt/rmwpen` ;
4. la création d'un environnement virtuel Python dédié dans `/opt/rmwpen/venv` ;
5. l'installation des dépendances Python (`openai`, `httpx`, `reportlab`, `python-docx`) ;
6. la création du lanceur exécutable `/usr/local/bin/rmwpen`.

Une fois installé, l'outil s'utilise depuis n'importe quel répertoire :

```bash
rmwpen -h
```

> Si l'outil n'est pas installé via `install.sh`, la commande équivalente reste `python3 main.py` depuis le dossier du projet, environnement virtuel activé.

## Désinstallation

```bash
sudo ./uninstall.sh
```

Supprime `/opt/rmwpen` ainsi que le lanceur `/usr/local/bin/rmwpen`.

## Utilisation

```bash
rmwpen [OPTIONS]
```

Schéma général d'une exécution :

```
rmwpen [OPTIONS]
   │
   ├── lit le fichier de scope (cible + règles d'engagement)
   ├── lance les agents d'investigation (contextes parallèles)
   ├── (à la fin, ou sur Ctrl+C) génère le rapport, réinjecte les vraies valeurs
   └── produit : files.zip + RAPPORT_PENTEST.pdf + RAPPORT_PENTEST.docx
```

Aide intégrée :

```bash
rmwpen -h
```

```
usage:   [-h] [-s SCOPE] [-m {apis,codex,codex_gemini,gemini}] [-e ENV]
         [-n MAX_CONTEXTS] [-f ZIP]

RMW-PenStrike — Autonomous Black-Box Pentest Tool.
Use -s to point to a scope file.
Use -m to choose the LLM backend.
Use -e to point to env.txt.
Use -n to set the maximum number of concurrent contexts (default 10).
Use -f to restore a previous snapshot (zip file).
```

## Options de la ligne de commande

| Option courte | Option longue | Obligatoire ? | Valeur par défaut | Rôle |
|---|---|---|---|---|
| `-h` | `--help` | non | — | Affiche l'aide et quitte |
| `-s` | `--scope` | non | `files/target.txt` | Fichier (ou dossier) décrivant la cible et le périmètre autorisé |
| `-m` | `--mode` | non | `gemini` | Moteur LLM utilisé : `apis`, `codex`, `gemini`, ou `codex_gemini` |
| `-e` | `--env` | **oui, si `-m apis`** | aucune | Fichier (ou dossier) contenant les clés API |
| `-n` | `--max-contexts` | non | `10` | Nombre de fils d'investigation traités en parallèle |
| `-f` | `--zip` | non | aucune | Archive de sauvegarde/reprise de session ; déclenche aussi la génération finale des livrables |

### Détail des modes LLM (`-m`)

| Mode | Mécanisme | Avantages | Inconvénients |
|---|---|---|---|
| `gemini` *(défaut)* | Invoque le CLI Gemini local en sous-processus | Simple une fois authentifié ; pas de clé API à gérer | Dépend d'une session interactive locale |
| `codex` | Invoque le CLI Codex (OpenAI) local en sous-processus | Indépendant de l'écosystème Google | Mêmes contraintes d'authentification locale |
| `codex_gemini` | Alterne entre Codex et Gemini ; bascule automatiquement vers le survivant en cas d'échec de l'un des deux | Tolérance aux pannes | Nécessite que les deux CLI soient installés |
| `apis` | Appelle directement les API officielles via une liste de clés (`env.txt`), avec rotation round-robin | Aucune session interactive requise ; seul mode utilisable en environnement non interactif (serveur, CI/CD) | Nécessite la gestion de clés API (`-e` obligatoire) |

## Fichiers de configuration

### Fichier de scope (`target.txt`)

Décrit la cible autorisée et les règles d'engagement. Constitue la preuve documentée du périmètre, indispensable d'un point de vue légal et méthodologique.

```text
Authorized targets:
https://cible-autorisee.exemple.com

Scope rules:
all

In scope:
all

Out of scope:
nothing

Objectives:
identifying vulnerabilities
```

### Fichier de clés API (`env.txt`)

Requis uniquement en mode `-m apis`. Sépare les clés selon la phase du pipeline pour éviter qu'une phase n'épuise le quota nécessaire à une autre.

```python
API_KEYS_PENTEST = [
    ["api_key", "base_url", "model1", "model2"],
    ["api_key2", "base_url", "model1"],
]
API_KEYS_EXECUTOR = [
    ["api_key", "base_url", "model1"],
]
API_KEYS_REPORT = [
    ["api_key", "base_url", "model1"],
]
```

## Anonymisation des données sensibles

Avant tout envoi à un LLM, les données sensibles détectées dans le scope, les commandes ou leurs résultats sont remplacées par des tokens de la forme `<CATEGORIE_NUMERO>` :

```text
<IP_001>
<URL_002>
<EMAIL_001>
<HASH_003>
<SECRET_014>
```

Le système combine trois mécanismes de détection :

- **détection par règles** (formats connus : IP, URL, email, hash, JWT...) ;
- **détection statistique** (score d'entropie pour repérer des secrets sans format prédéfini) ;
- **détection assistée par IA** (un LLM identifie les informations sensibles résiduelles).

Une table de correspondance locale (`mapping.txt`) associe chaque token à sa valeur réelle. **Cette table n'est jamais transmise au LLM.** Juste avant l'exécution d'une commande, les tokens sont remplacés par les vraies valeurs localement ; les résultats sont ensuite ré-anonymisés avant d'être renvoyés au modèle.

Un contrôle de sécurité supplémentaire bloque l'exécution de commandes dangereuses (accès à `/etc/`, `/root/`, `/proc/`, usage de `sudo`, `docker`, `mount`, `chroot`, etc.) et confine l'exécution dans un répertoire de travail contrôlé.

## Génération du rapport

À la fin de l'engagement (ou à l'arrêt manuel via `Ctrl+C`), l'outil transforme les contextes d'investigation bruts en un livrable professionnel, en quatre étapes :

1. **Génération** — transformation des contextes en un document Markdown structuré, via le LLM, selon un gabarit imposé (structure type cabinet de pentest, alignée OWASP Testing Guide / CVSS / CWE).
2. **Enrichissement** — corrélation automatique des vulnérabilités identifiées avec des bases de données publiques (CVE, exploits).
3. **Réinjection (mapping)** — remplacement des placeholders anonymisés par les véritables données de la cible.
4. **Mise en forme finale** — conversion en PDF et Word, et empaquetage des livrables.

Livrables produits :

- `RAPPORT_PENTEST_<timestamp>.pdf`
- `RAPPORT_PENTEST_<timestamp>.docx`
- `files.zip` (archive de session complète, réutilisable pour reprendre un engagement interrompu)

## Exemples d'utilisation

**Lancement standard :**
```bash
rmwpen -s target.txt -m gemini -f engagement_client_X.zip
```

**Environnement automatisé / sans interaction (CI, serveur distant) :**
```bash
rmwpen -s target.txt -m apis -e env.txt -n 5 -f files.zip
```

**Reprise d'un engagement interrompu** (si `engagement_client_X.zip` existe déjà, son contenu est restauré automatiquement) :
```bash
rmwpen -s target.txt -m gemini -f engagement_client_X.zip
```

**Débogage / test à faible échelle :**
```bash
rmwpen -s target_test.txt -m gemini -n 1
```

**Bascule de secours entre deux moteurs LLM :**
```bash
rmwpen -s target.txt -m codex_gemini -n 3
```

## Avertissement légal

RMW-PenStrike est destiné exclusivement à des tests d'intrusion **autorisés**, réalisés dans le cadre d'un mandat explicite et d'un périmètre défini par écrit. Toute utilisation de cet outil contre un système sans autorisation préalable est illégale. Le fichier de scope (`target.txt`) doit toujours refléter un périmètre réellement autorisé par le propriétaire de la cible.

---

*Projet réalisé dans le cadre d'un projet de fin d'année — 2025-2026.*
