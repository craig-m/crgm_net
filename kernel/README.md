# kernel config

Build a custom, lightweight, linux kernel for Linode Linux VPS (on the remote destination machine).

"Tested" with Debian GNU/Linux 9.6 (stretch) + 4.20.14 (current stable), on my Linode. This is not endorsed or supported by me in anyway.


to do: continue to turn things off until something breaks. This kernel already uses far less memory than the default one :)


### hardening

The config was aided by the use of this tool: https://github.com/a13xp0p0v/kconfig-hardened-check

```
git clone https://github.com/a13xp0p0v/kconfig-hardened-check.git
```

Loadable kernel modules and kexec etc have been disabled.
