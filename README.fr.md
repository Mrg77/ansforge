# ansforge

*Read this in [English](README.md).*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Un agent IA qui écrit, valide et sécurise de l'Ansible — en l'exécutant, pas en le lisant.**

`ansible-lint` valide la **forme**. Il ne peut pas vous dire qu'un template
référence une variable qui n'existera pas sur la machine, qu'une configuration est
du YAML valide et pourtant refusée par le démon qui la consomme, ou qu'un playbook
rapportera `changed` indéfiniment parce qu'une tâche n'a pas de `changed_when`.

ansforge comble cet écart. Il rend les templates **par Ansible lui-même**, valide le
résultat avec **l'outil amont dans un conteneur**, et vérifie l'idempotence en
**jouant deux fois**. Toute action qui touche une machine réelle passe par une
**policy-as-code** : l'agent aide sans pouvoir converger la production par accident.

Écrit **from scratch sur l'API Anthropic Messages** — sans framework, la boucle
agentique est entièrement visible.

> Pas un « LLM qui écrit du YAML » de plus. La valeur, c'est la preuve : un agent
> dont on vérifie le travail, dont on borne la portée, et dont on voit la dépense.

## Pourquoi cet outil existe

Trois bugs d'une plateforme AWS réelle, tous passés au travers d'`ansible-lint` en
profil production :

1. **`{{ ansible_managed }}` dans le `content:` d'un module `copy`.** Cette variable
   n'est injectée que par le module `template`. Le lint voyait du Jinja valide. Un
   test Python fournissait la variable à la main et passait aussi. L'instance a
   planté au premier boot.
2. **`stub_status` sur `listen 127.0.0.1:8080` dans un conteneur.** `nginx -t`
   déclarait la configuration correcte. Mais cette adresse est la loopback *du
   conteneur* — inatteignable depuis l'hôte, où tourne l'exporter Prometheus. La
   supervision serait devenue aveugle en silence.
3. **La rotation des logs disparue avec le paquet qui la fournissait.** Conteneuriser
   nginx a retiré le RPM, et avec lui `/etc/logrotate.d/nginx`. Rien n'était
   syntaxiquement faux. L'access log aurait saturé le volume racine.

Aucun n'était détectable sans exécuter. C'est la thèse de l'outil.

## Installer

```sh
go install github.com/Mrg77/ansforge@latest
```

## Utiliser

```sh
export ANTHROPIC_API_KEY=...     # console.anthropic.com, facturé au token

ansforge "rends les templates de roles/nginx avec group_vars/all et corrige ce qui casse"
ansforge "ajoute no_log à chaque tâche manipulant un secret dans roles/grafana"
```

Et une sous-commande déterministe, sans clé API — utilisable comme gate de CI,
parce qu'un gate doit être reproductible :

```sh
ansforge scan .                      # sort en 1 sur un finding high
ansforge scan roles/ --fail-on medium
```

## La garde

En Ansible, l'acte destructeur n'a pas de nom effrayant. Il n'y a pas de verbe
`destroy` — `ansible-playbook` sur un inventaire change simplement des machines, et
ça se lit comme une commande de routine. C'est précisément pour ça qu'il faut un
garde explicite.

| Action | Contexte production | Ailleurs |
|---|---|---|
| `playbook_run` | **refusé** | confirmation |
| `idempotence_check` | **refusé** | confirmation |
| `playbook_check` | confirmation | autorisé |
| lint, render, validate, scan | autorisé | autorisé |

La production est détectée **passivement** — motif `limit`, chemin d'inventaire,
chemin du playbook — jamais en se connectant. Un contexte inconnu **échoue fermé** :
une action destructrice ne passe pas au prétexte qu'on n'a pas su identifier
l'environnement. Une politique vide retombe sur la politique par défaut plutôt que
de tout autoriser en silence.

## Ce qu'il ne fera pas

- **Il ne peut pas atteindre vos machines seul.** Tout run réel est gardé, et sans
  terminal (CI, pipe) une confirmation devient un refus.
- **Il ne peut pas sortir du projet.** Tout chemin est confiné au répertoire de
  travail. `../../etc/passwd` est une erreur, pas une traversée.
- **Il n'affirme pas ce qu'il n'a pas vérifié.** Si ansible ou docker manque, il dit
  que le contrôle n'a pas eu lieu. Le silence ne doit jamais se lire comme un succès.

## LLMOps

Chaque tour de modèle, appel d'outil et décision de garde est journalisé en JSONL,
avec les tokens valorisés :

```sh
ANSFORGE_AUDIT=off ansforge "..."        # pas de fichier ; le résumé s'affiche quand même
ANSFORGE_MAX_COST=0.50 ansforge "..."    # s'arrête avant de dépasser 0,50 USD
```

Auditabilité et visibilité de la dépense : c'est ce qui rend un agent déployable.

## Licence

MIT.
