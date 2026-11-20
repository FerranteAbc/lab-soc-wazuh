# Laboratório de Detecção (SOC Lab) — Wazuh + Hyper-V

Laboratório doméstico de SIEM/detecção, construído do zero em Hyper-V, para treino prático de Blue Team (análise de logs, criação/validação de regras, mapeamento MITRE ATT&CK e resposta a incidentes).

## Objetivo

Simular ataques reais contra um alvo controlado, capturar a detecção no Wazuh, mapear para o MITRE ATT&CK e documentar a cadeia completa **ataque → evento → alerta → técnica → resposta**, com evidências reais (não apenas teoria).

## Topologia

```
                    ┌─────────────────────┐
                    │   Host (Windows)     │
                    │   Hyper-V            │
                    └──────────┬───────────┘
                               │
              Switch interno "Rede-Pentest" (10.10.10.0/24)
              isolado da internet durante os testes
                               │
      ┌────────────────────────┼────────────────────────┐
      │                        │                         │
┌─────┴──────┐         ┌───────┴────────┐        ┌───────┴────────┐
│ wazuh-siem │         │  linux-alvo    │        │     Kali        │
│10.10.10.10 │◄────────┤ 10.10.10.50    │◄───────┤  10.10.10.30    │
│ Ubuntu 24.04│  dados  │ Ubuntu 24.04   │ ataque │  ferramentas    │
│ Wazuh 4.14  │  agente │ agente Wazuh   │        │  ofensivas      │
│(manager +   │         │                │        │  (Hydra, etc.)  │
│ indexer +   │         │                │        │                 │
│ dashboard)  │         │                │        │                 │
└─────────────┘         └────────────────┘        └─────────────────┘
```

Cada VM também tem uma segunda placa de rede ligada a um switch com acesso à internet (usada só para instalação de pacotes), desligada/isolada durante os testes de ataque.

## Componentes

| VM | IP (lab) | SO | Papel |
|---|---|---|---|
| `wazuh-siem` | 10.10.10.10 | Ubuntu 24.04.5 LTS | Wazuh manager + indexer + dashboard (all-in-one) |
| `linux-alvo` | 10.10.10.50 | Ubuntu 24.04.5 LTS | Alvo monitorado, agente Wazuh instalado |
| `Kali_Linux_Pentest` | 10.10.10.30 | Kali Linux | Máquina atacante |

## Setup realizado

1. Criação das VMs no Hyper-V, rede interna isolada `Rede-Pentest`.
2. Instalação do Wazuh (all-in-one) na `wazuh-siem` via script oficial (`wazuh-install.sh -a`).
3. Instalação e registro do agente Wazuh na `linux-alvo` via assistente do dashboard.
4. Configuração de IP estático nas três VMs na rede isolada.
5. Checkpoints automáticos do Hyper-V desativados (causavam esgotamento de disco).

## Testes de detecção realizados

- [**Fase 1 — Força bruta SSH (T1110)**](docs/fase1-forca-bruta-ssh.md): ataque de dicionário via Hydra contra a `linux-alvo`, detecção pelo Wazuh (regras 5760 e 40112), mapeamento MITRE ATT&CK (T1110.001, T1078) e resposta automática (bloqueio de IP via Active Response).

## Próximos passos

- Fase 2: VM Windows com Sysmon + agente Wazuh, simulação de técnicas com Atomic Red Team.
- Cobrir mais gaps do MITRE ATT&CK (persistência, exfiltração, impacto).
- Diagrama de arquitetura em formato visual (draw.io/SVG).
