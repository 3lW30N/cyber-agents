# Architecture initiale

Le dépôt est structuré autour de deux stacks :

- `stacks/proprietary` : intégration à des services propriétaires (LLM, SIEM, outils internes)
- `stacks/opensource` : intégration à des composants open source

Chaque stack contient :

- `stack.yaml` : paramètres globaux de la stack
- `agents.yaml` : définition de la flotte Blue/Red (rôles, capacités, canaux)

## Rôles d’agents

- Blue team
  - `blue-soc-analyst` : triage d’alertes et corrélation
  - `blue-incident-responder` : réponse et remédiation guidée
- Red team
  - `red-operator` : simulation d’attaques
  - `red-planner` : planification de scénarios adversaires

## Convention de configuration

- `team`: `blue` ou `red`
- `mode`: `assistive` ou `autonomous`
- `capabilities`: liste des actions autorisées
- `tools`: intégrations disponibles pour l’agent
