#!/bin/bash

# varibles ---------------------------------------------------------------------
# VARS are set in environment var (see readme.md)

echo -e "\nEnvironment varibles:\n"

echo -e "env var: vm_name: $vm_name"
[[ ! -z "$vm_name" ]] || exit 1

echo -e "env var: vm_root_pw: $vm_root_pw"
[[ ! -z "$vm_root_pw" ]] || exit 1

echo -e "env var: vm_username: $vm_username"
[[ ! -z "$vm_username" ]] || exit 1

echo -e "env var: vm_user_pw: $vm_user_pw"
[[ ! -z "$vm_user_pw" ]] || exit 1

echo -e "env var: vm_ip_whitelist: $vm_ip_whitelist"
[[ ! -z "$vm_ip_whitelist" ]] || exit 1

echo -e "env var: stackscriptname: $stackscriptname"
[[ ! -z "$stackscriptname" ]] || exit 1

echo -e "\n"


# functions --------------------------------------------------------------------

apijson(){
  # used when creating a linode
  echo "Using temp json payload: "
  script_temp_dir=$(mktemp -d)
  script_temp_file=$(uuid -F SIV | cut -b 10-25)
  touch -f $script_temp_dir/$script_temp_file
  chmod 600 $script_temp_dir/$script_temp_file
  tempjson="$script_temp_dir/$script_temp_file"
cat > $tempjson << EOF
{
   "deployuser":"${vm_username}",
   "deployeruserpassword":"${vm_user_pw}",
   "sshipwhitelist":"${vm_ip_whitelist}"
}
EOF
  ls -la $tempjson
}

testsshup(){
  # The stackscript will take a couple more min to complete,
  # SSHD will be down until it finishes.
  ssh -i /home/vagrant/.ssh/id_rsa_node \
  -o ConnectTimeout=15 \
  -o ConnectionAttempts=10 \
  -o StrictHostKeyChecking=no \
  ${vm_username}@${vm_ip_addr} uptime;
}


# Check StackScript exists - create is missing ---------------------------------
echo -e "\nStackScript:\n"

linode-stackscript list -l $stackscriptname | grep $stackscriptname;
if [ $? -eq 1 ]; then
  echo "creating missing stackscript";
  linode-stackscript -a create \
    --label="$stackscriptname" \
    --revnote="auto_v0.9 prod" \
    --ispublic="no" \
    --distribution="Debian 9" \
    --description="crgm.net Debian 9 Stretch base setup." \
    --codefile="/vagrant/stackscript.sh";
else
  echo "updating stackscript";
  linode-stackscript -a update --label="$stackscriptname" \
    --revnote="prod" --codefile="/vagrant/stackscript.sh";
fi


# Create VM --------------------------------------------------------------------
echo -e "\nVM:\n"

# check if Linode exists
linode-linode list -l ${vm_name} | grep -v "Couldn't find" | grep ${vm_name}
if [ $? -eq 1 ]; then
  echo "creating new linode "
  # temp json payload
  apijson
  # create a new VPS!
  linode create $vm_name \
    --label $vm_name \
    --distribution "Debian 9" \
    --stackscript ${stackscriptname} \
    --password  ${vm_root_pw} \
    --pubkey-file /home/vagrant/.ssh/id_rsa_node.pub \
    --stackscriptjson ${tempjson};
  # exit if provision fails
  if [ $? -eq 1 ]; then
    echo "failed to create linode!"
    exit 1;
  fi
  echo "waiting a moment.. ."
  sleep 45s;
  linode-linode -a show --label ${vm_name}
  vm_created="true"
else
  echo "the VM ${vm_name} already exists"
  vm_created="false"
fi


# get VM IP from Linode API
vm_ip_addr=$(linode-linode -a show --label ${vm_name} | tail -n2 | tr -d '\n' | awk '{print $2}')


# continue when SSH is up on VM
until testsshup
do
	echo "SSHD on ${vm_name} up"
done


# next stage of VM setup (if new)
if [ true = $vm_created ]; then
  echo "calling stage2 of VM setup"
  sleep 30s;
  ssh -i /home/vagrant/.ssh/id_rsa_node -t \
  ${vm_username}@${vm_ip_addr} \
  hostname; echo true > /mnt/ramstore/data/stage2; id;
else
  echo "NOT calling stage2"
fi


# done
echo -e "\ncreate_linode.sh finished.\n"
