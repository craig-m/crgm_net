#!/bin/bash

cd ~/Downloads
wget https://dl.google.com/go/go1.11.4.linux-amd64.tar.gz
tar -xf -- go1.11.4.linux-amd64.tar.gz
sudo mv go/ /usr/local/

mkdir ~/gopath/src

export GOROOT=/usr/local/go
export GOPATH=$HOME/gopath
export PATH=$GOROOT/bin:$GOPATH/bin:$PATH

echo "export GOROOT=/usr/local/go" >> $HOME/.bashrc
echo "export GOPATH=$HOME/gopath" >> $HOME/.bashrc
echo "export PATH=$GOROOT/bin:$GOPATH/bin:$PATH" >> $HOME/.bashrc
