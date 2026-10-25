# MCP Auth Proxy — édition multi-utilisateurs FIAB

Proxy OAuth 2.1 (PKCE et enregistrement dynamique DCR) placé devant des serveurs MCP, par exemple des workflows n8n.
Chaque utilisateur a son identifiant, son mot de passe, son URL MCP de destination et ses en-têtes. Tout se gère depuis un tableau de bord admin.

Fork de [sigbit/mcp-auth-proxy](https://github.com/sigbit/mcp-auth-proxy) (licence MIT).
Modifications © Ives FASSINOU (FIAB Web Identity).

## Fonctionnement

- URL publique par utilisateur : `{EXTERNAL_URL}/u/{slug}/mcp`.
- Le jeton OAuth est lié à un utilisateur. Sur `/u/B/mcp`, un jeton de l'utilisateur A est refusé (403).
- La requête part uniquement vers l'URL de destination de l'utilisateur, avec ses en-têtes.
  `Authorization`, `Cookie` et les en-têtes du client portant le même nom sont toujours supprimés.
- Désactiver, supprimer ou « Révoquer sessions et jetons » coupe l'accès immédiatement, même avec un jeton encore valide.
- Les valeurs d'en-têtes sont chiffrées au repos (AES-256-GCM). Elles ne sont jamais réaffichées.

## Variables d'environnement

| Variable | Obligatoire | Rôle |
|---|---|---|
| `EXTERNAL_URL` | oui | URL publique, ex. `https://mcp.example.com` (sans chemin) |
| `NO_AUTO_TLS` | oui derrière Traefik | `true` : TLS géré par Traefik / Coolify |
| `DATA_PATH` | non | Données persistantes, `/data` dans l'image Docker |
| `TRUSTED_PROXIES` | **oui derrière Traefik** | IP ou plage CIDR de Traefik, pour lire la vraie IP du client (blocage, liste d'IP admin) |
| `ADMIN_USERNAME` | oui | Identifiant admin. Active le mode multi-utilisateurs |
| `ADMIN_PASSWORD_HASH` | oui | Hash bcrypt du mot de passe admin (base64 recommandé, voir ci-dessous) |
| `ENCRYPTION_KEY` | oui | 32 octets en base64. **Le proxy refuse de démarrer sans elle.** |
| `ADMIN_TOTP_SECRET` | recommandé | Secret TOTP base32. Si défini, le code Google Authenticator est obligatoire |
| `ADMIN_PATH` | non | Chemin du tableau de bord, `/admin` par défaut |
| `ADMIN_ALLOWED_IPS` | non | IP ou plages CIDR autorisées sur le tableau de bord, séparées par des virgules. Les autres reçoivent une 404 |
| `REPOSITORY_BACKEND` / `REPOSITORY_DSN` | non | `local` (bbolt, défaut) ou `sqlite`, `postgres`, `mysql` |

En mode multi-utilisateurs, `PASSWORD`, `PASSWORD_HASH`, `PROXY_HEADERS`, `PROXY_BEARER_TOKEN`, les fournisseurs Google, GitHub et OIDC et l'URL cible en argument sont refusés au démarrage.
Sans `ADMIN_USERNAME`, le proxy fonctionne exactement comme le projet d'origine.

> ⚠️ Sauvegardez `ENCRYPTION_KEY`. Si elle est perdue ou changée, les en-têtes enregistrés deviennent illisibles : il faudra les ressaisir.

## Générer les secrets

Avec Docker, sans installer Go (remplacez l'image par la vôtre, ou utilisez `go run .` dans le dépôt) :

```bash
docker build -t mcp-auth-proxy-fiab .
```

```bash
docker run --rm -i mcp-auth-proxy-fiab hash-password
```

Saisissez le mot de passe admin (12 caractères minimum) puis Entrée. La commande affiche `ADMIN_PASSWORD_HASH=...`.
Le hash est encodé en base64, car un hash bcrypt brut (`$2a$...`) est altéré par l'interpolation des `$` de Docker Compose. Les deux formats sont acceptés.

```bash
docker run --rm mcp-auth-proxy-fiab gen-secrets --admin-username admin
```

La commande affiche `ENCRYPTION_KEY`, `ADMIN_TOTP_SECRET` et un lien `otpauth://`. Ajoutez le secret dans Google Authenticator (saisie manuelle ou QR code généré à partir du lien).

## Déploiement sur Coolify

1. Créez une ressource **Docker Compose** pointant sur ce dépôt, fichier [`docker-compose.coolify.yml`](docker-compose.coolify.yml).
2. Associez votre domaine au service `mcp-auth-proxy`, port **80** (ex. `https://mcp.example.com:80` dans le champ Domaine).
3. Renseignez les variables dans l'onglet **Environment Variables** de Coolify.
4. Pour `TRUSTED_PROXIES`, mettez le sous-réseau du réseau Docker de Traefik. Pour le connaître, sur le serveur :

   ```bash
   docker network inspect coolify --format '{{(index .IPAM.Config 0).Subnet}}'
   ```

5. Déployez, puis ouvrez `https://mcp.example.com/admin`.

Le volume `mcp-proxy-data` conserve les clés, la base OAuth et `fiab.db` (utilisateurs et journal). Ne le supprimez pas.

## Ajouter un utilisateur

1. Tableau de bord › **Nouvel utilisateur** : identifiant (slug, non modifiable), nom affiché, mot de passe, URL MCP de destination (ex. l'URL du nœud MCP Server Trigger de n8n).
2. Sur la fiche de l'utilisateur, section **En-têtes injectés** : ajoutez par exemple `x-api-key` avec la valeur attendue par n8n.
3. **Tester la connexion** envoie une requête MCP `initialize` et affiche OK ou l'erreur.
4. Copiez l'**URL publique** (`https://mcp.example.com/u/{slug}/mcp`) et transmettez-la à l'utilisateur avec son identifiant et son mot de passe.

## Connexion depuis Claude.ai

1. Paramètres › **Connecteurs** › **Ajouter un connecteur personnalisé**.
2. Nom au choix, URL : `https://mcp.example.com/u/{slug}/mcp`. Laissez les champs OAuth avancés vides : le client s'enregistre automatiquement (DCR).
3. Cliquez sur **Se connecter**. La page de connexion du proxy s'ouvre, identifiant prérempli.
4. Saisissez le mot de passe, puis **Autoriser** sur la page « Autoriser Claude à accéder à votre espace ? ».

Même URL pour Claude Desktop. Pour Claude Code :

```bash
claude mcp add --transport http mon-espace https://mcp.example.com/u/mon-slug/mcp
```

## Sécurité du tableau de bord

- Mot de passe bcrypt uniquement, TOTP obligatoire si `ADMIN_TOTP_SECRET` est défini, codes déjà utilisés refusés.
- Blocage temporaire : 5 échecs par identifiant ou 20 par IP en 15 minutes donnent 15 minutes de blocage, pour l'admin comme pour les utilisateurs. Les compteurs sont en mémoire et repartent à zéro au redémarrage.
- Session admin en mémoire : cookie HttpOnly, Secure, SameSite=Strict. Expiration après 15 minutes d'inactivité, 2 heures maximum.
- Jeton CSRF sur tous les formulaires. CSP stricte, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`.
- Journal des actions admin (qui, quoi, quand, IP) : 1000 dernières entrées, aucun secret.

Le cookie de session utilisateur reste en `SameSite=Lax`, sinon le retour depuis claude.ai pendant le parcours OAuth échouerait.

## Développement

```bash
go test ./...
```

```bash
go build -o bin/mcp-auth-proxy .
```

Le code ajouté se trouve dans `pkg/fiab` (`store`, `security`, gabarits dans `pkg/fiab/web`).
Le code d'origine ne reçoit que des points d'accroche, repérés par les commentaires `!fiab:`, pour pouvoir récupérer facilement les correctifs de sigbit.
Documentation du projet d'origine : https://sigbit.github.io/mcp-auth-proxy/
