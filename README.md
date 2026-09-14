# cyber-agents

Initialisation d’un projet pour opérer une flotte d’agents cyber **Blue team** et **Red team** sur :

- une stack **propriétaire**
- une stack **100% open source**

## Structure

```text
.
├── stacks
│   ├── opensource
│   │   ├── agents.yaml
│   │   └── docker-compose.yml
│   └── proprietary
│       ├── agents.yaml
│       └── docker-compose.yml
└── .env.example
```

## Démarrage rapide

1. Copier les variables d’environnement :

```bash
cp .env.example .env
```

2. Lancer la stack open source :

```bash
docker compose -f /home/runner/work/cyber-agents/cyber-agents/stacks/opensource/docker-compose.yml up -d
```

3. Lancer la stack propriétaire :

```bash
docker compose -f /home/runner/work/cyber-agents/cyber-agents/stacks/proprietary/docker-compose.yml up -d
```

## Notes

- Les fichiers `agents.yaml` décrivent la flotte Blue/Red (rôle, mission, capacité).
- Les images de la stack propriétaire sont des placeholders à remplacer par vos images internes.
