# cyber-agents

Flotte d’agents cyber Blue team et Red team sur une stack propriétaire et sur une stack 100% open source.

## Objectif

Ce dépôt initialise une base de travail pour :

- orchestrer des agents Blue team (défense, détection, réponse)
- orchestrer des agents Red team (attaque simulée, émulation adversaire)
- comparer une stack propriétaire et une stack open source

## Structure

```text
.
├── docs/
│   └── ARCHITECTURE.md
├── stacks/
│   ├── opensource/
│   │   ├── agents.yaml
│   │   └── stack.yaml
│   └── proprietary/
│       ├── agents.yaml
│       └── stack.yaml
└── .env.example
```

## Démarrage rapide

1. Copier les variables d’environnement :
   - `cp .env.example .env`
2. Renseigner les clés et endpoints nécessaires selon la stack visée.
3. Adapter les fichiers `stacks/*/*.yaml` selon vos cas d’usage.

## Prochaine étape recommandée

- Ajouter un orchestrateur d’exécution (CLI ou service) lisant les fichiers de stack et d’agents.
