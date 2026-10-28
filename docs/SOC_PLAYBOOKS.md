# Response playbooks

Playbooks live in `config/playbooks/*.yaml` (add your own in `<data dir>/playbooks/`).

```yaml
name: block_ip
title: Block attacker IP
target: src_ip                 # the alert/request must provide this field
actions:
  - {type: block_ip, ip: "{src_ip}"}
  - {type: add_ioc, value: "{src_ip}", description: "Blocked after alert {alert_id}"}
  - {type: notify, message: "Blocked {src_ip} after '{rule_name}'"}
```

Placeholders: `{src_ip} {dst_ip} {hostname} {user} {alert_id} {rule_name} {severity} {entity}`.

| Action | Effect in `enforce` mode | Needs approval (default) |
|---|---|---|
| `block_ip` | Windows Firewall rule / iptables DROP; auto-unblock after `block_duration` | yes |
| `isolate_host` | POST to `response.edr.isolate_webhook` | yes |
| `disable_user` | POST to `response.identity.disable_webhook` | yes |
| `add_ioc` | adds the value to threat intel (saved) | no |
| `notify` | Slack / Teams / webhook / e-mail | no |

## How a response happens

1. A new alert at or above `auto_response.min_severity` suggests playbooks (the rule's
   `response:` list), or an analyst picks one in the alert panel or on the Response tab.
2. The request is rendered and validated. If it contains an action listed in
   `approval.required_for`, it waits in **Response → Waiting for approval**.
3. Approve runs it. In `dry_run` mode every action is recorded as `dry_run` and nothing
   on your systems changes. Reject records the reason.
4. Every step is written to `logs/audit.log`.

## Triage workflow

`new` → `investigating` (assign yourself, add notes) → `contained` (after response) →
`resolved`, or `false_positive`. Tune the rule (Detection tab) if it keeps firing on benign activity.
