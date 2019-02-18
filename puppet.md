# puppet bolt

First get the IP address of the Linode:

```
vm_ip_addr=$(linode-linode -a show --label ${vm_name} | tail -n2 | tr -d '\n' | awk '{print $2}')
```

## using bolt

Run a command on the Linode via Bolt:

```
bolt command run id \
  --host-key-check --no-host-key-check \
  --nodes ${vm_username}@${vm_ip_addr}
```

Install a package:

```
bolt task run package action=install name=emacs \
  --host-key-check --no-host-key-check \
  --nodes ${vm_username}@${vm_ip_addr} \
  --run-as root --sudo-password $vm_user_pw
```

Run a script as root:

```
bolt script run /vagrant/scripts/ufw.sh \
  --host-key-check --no-host-key-check \
  --nodes ${vm_username}@${vm_ip_addr} \
  --run-as root --sudo-password $vm_user_pw
```
