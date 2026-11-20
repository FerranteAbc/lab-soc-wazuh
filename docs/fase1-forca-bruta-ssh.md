# Fase 1 — Força Bruta SSH (T1110)

## Resumo

Simulação de um ataque de força bruta via SSH contra a `linux-alvo` (10.10.10.50), usando Hydra a partir da Kali (10.10.10.30), com captura completa da detecção no Wazuh e validação de uma resposta automática (bloqueio de IP).

## Ambiente

- **Atacante:** Kali Linux — 10.10.10.30
- **Alvo:** `linux-alvo`, Ubuntu 24.04.5 LTS — 10.10.10.50, usuário `aluno-teste`
- **SIEM:** `wazuh-siem`, Wazuh 4.14 — 10.10.10.10
- **Ferramenta:** Hydra v9.6

## 1. Ataque

Wordlist com 15 senhas incorretas + a senha correta (`lab2026`) ao final, simulando um ataque de dicionário:

```bash
hydra -l aluno-teste -P senhas.txt ssh://10.10.10.50 -t 4
```

Resultado:

```
[DATA] max 4 tasks per 1 server, overall 4 tasks, 16 login tries (l:1/p:16), ~4 tries per task
[DATA] attacking ssh://10.10.10.50:22/
[22][ssh] host: 10.10.10.50   login: aluno-teste   password: lab2026
1 of 1 target successfully completed, 1 valid password found
```

## 2. Evento (log bruto capturado pelo agente)

Tentativa falhada:
```
Nov 20 14:33:05 linux-alvo sshd[5330]: Failed password for aluno-teste from 10.10.10.30 port 35806 ssh2
```

Tentativa com sucesso (última da lista):
```
Nov 20 14:33:05 linux-alvo sshd[5330]: Accepted password for aluno-teste from 10.10.10.30 port 35806 ssh2
```

## 3. Alertas gerados pelo Wazuh

### Regra 5760 — evento individual de falha

| Campo | Valor |
|---|---|
| `rule.id` | 5760 |
| `rule.level` | 5 |
| `rule.description` | sshd: authentication failed. |
| `rule.mitre.id` | T1110.001, T1021.004 |
| `rule.mitre.technique` | Password Guessing, SSH |
| `data.srcip` | 10.10.10.30 |
| `data.dstuser` | aluno-teste |

> Observação: o Wazuh também marcou `T1021.004` (Lateral Movement) nesse evento. Isso é uma associação genérica que a regra faz com qualquer evento do grupo `sshd`, não uma indicação real de movimento lateral neste caso — vale registrar essa limitação do mapeamento automático.

### Regra 40112 — correlação (o alerta relevante)

| Campo | Valor |
|---|---|
| `rule.id` | 40112 |
| `rule.level` | **12** |
| `rule.description` | Multiple authentication failures followed by a success. |
| `rule.frequency` | 2 |
| `rule.mitre.id` | T1078, T1110 |
| `rule.mitre.technique` | Valid Accounts, Brute Force |
| `rule.mitre.tactic` | Credential Access, Initial Access, Privilege Escalation, Persistence, Defense Evasion |
| `data.srcip` | 10.10.10.30 |
| `data.dstuser` | aluno-teste |
| `full_log` | `Accepted password for aluno-teste from 10.10.10.30 port 35806 ssh2` |

Essa é a regra de correlação: ela só dispara quando várias falhas de autenticação são seguidas por um login bem-sucedido da mesma origem — o padrão clássico de uma senha comprometida por força bruta.

## 4. Resposta (Active Response)

Configurada no manager (`wazuh-siem`, `/var/ossec/etc/ossec.conf`):

```xml
<ossec_config>
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>40112</rules_id>
    <timeout>600</timeout>
  </active-response>
</ossec_config>
```

Quando a regra 40112 dispara, o manager instrui o próprio agente (`linux-alvo`) a bloquear o IP de origem via `iptables`, por 600 segundos.

### Log da resposta ativa (`/var/ossec/logs/active-responses.log`)

```
2026/11/20 14:33:06 active-response/bin/firewall-drop: Starting {"command":"add", ... "rule":{"level":12,"id":"40112", ...}, "srcip":"10.10.10.30", ...}
2026/11/20 14:33:06 active-response/bin/firewall-drop: {"command":"check_keys","parameters":{"keys":["10.10.10.30"]}}
2026/11/20 14:33:06 active-response/bin/firewall-drop: {"command":"continue", ...}
2026/11/20 14:33:06 active-response/bin/firewall-drop: Ended
```

### Confirmação via `iptables` na `linux-alvo`

```
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
DROP       0    --  10.10.10.30          0.0.0.0/0

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
DROP       0    --  10.10.10.30          0.0.0.0/0
```

### Validação prática

Nova tentativa de SSH a partir da Kali, logo após o bloqueio:

```bash
ssh aluno-teste@10.10.10.50
```

Resultado: conexão trava e expira (timeout) — os pacotes da Kali estão sendo descartados silenciosamente (`DROP`) pelo `iptables`, confirmando que a resposta automática funcionou.

## Conclusão

O ciclo completo foi validado de ponta a ponta:

**Ataque (Hydra)** → **Evento (sshd log)** → **Alerta (regras 5760 / 40112)** → **Técnica MITRE (T1110.001 / T1078)** → **Resposta automática (firewall-drop via iptables)**

O Wazuh detectou corretamente o padrão de força bruta seguido de comprometimento, e a resposta ativa cortou o acesso contínuo do atacante após o login bem-sucedido — um cenário realista de contenção pós-comprometimento.
