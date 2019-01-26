#!/bin/bash

# add environment varibles, and then run with create|rebuild. eg:
#
# ./create_linode.sh create

# varibles ---------------------------------------------------------------------
# VARS are set in environment var (see readme.md)

echo -e "\nEnvironment varibles (will exit if unset):\n"

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
  # used when {re,cr}eating a linode
  echo -e "\nUsing temp json payload: "
  # make a temp dir
  script_temp_dir=$(mktemp -d)
  script_temp_file=$(uuid -F SIV | cut -b 10-25)
  touch -f $script_temp_dir/$script_temp_file
  chmod 600 $script_temp_dir/$script_temp_file
  tempjson="$script_temp_dir/$script_temp_file"
cat > $tempjson << EOF
{
   "deployuser":"${vm_username}",
   "deployeruserpassword":"${vm_user_pw}",
   "sshipwhitelist":"${vm_ip_whitelist}",
   "vm_name":"${vm_name}",
   "github_user":"craig-m",
   "github_repo":"crgm_net"
}
EOF
  ls -la $tempjson
}

testsshup(){
  # The stackscript will take a couple more min to complete,
  # SSHD will be down until it finishes.
  #
  # get VM IP from Linode API
  vm_ip_addr=$(linode-linode -a show --label ${vm_name} | tail -n2 | tr -d '\n' | awk '{print $2}')
  #
  # ssh
  ssh -i /home/vagrant/.ssh/id_rsa_node \
  -o ConnectTimeout=25 \
  -o ConnectionAttempts=10 \
  -o StrictHostKeyChecking=no \
  ${vm_username}@${vm_ip_addr} uptime;
}


stackscript(){
  # check stackscript exists and upload if missing
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
}


linode_manage(){
  echo -e "\creating new linode:\n"
  # temp json payload
  apijson
  # setup fresh Debian install
  linode $nodeact $vm_name \
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
}


linode_rebuild(){
  # check if Linode exists
  linode-linode list -l ${vm_name} | grep -v "Couldn't find" | grep ${vm_name}
  if [ $? -eq 1 ]; then
    echo "ERROR: the VM ${vm_name} does not exists"
    exit 1;
  else
    linode_manage
  fi
}


linode_create(){
  # check if Linode exists
  linode-linode list -l ${vm_name} | grep -v "Couldn't find" | grep ${vm_name}
  if [ $? -eq 1 ]; then
    echo "No VM named ${vm_name} - creating"
    linode_manage
  else
    echo "ERROR: the VM ${vm_name} already exists"
    exit 1;
  fi
}


# build VM ---------------------------------------------------------------------


case "$1" in
        create)
            nodeact="create"
            linode_create
            ;;
        rebuild)
            nodeact="rebuild"
            linode_rebuild
            ;;
        *)
            echo $"Usage: $0 {create|rebuild}"
            exit 1
esac


# continue when SSH is up on VM
until testsshup
do
	echo "SSHD on ${vm_name} up"
done


# done
echo -e "\ncreate_linode.sh finished.\n"
