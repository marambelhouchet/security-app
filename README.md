﻿# security-app
 Description générale :
Ce projet consiste à développer une plateforme web sécurisée en utilisant Flask et Python. L'objectif est de fournir une solution où les utilisateurs peuvent se connecter, interagir et sécuriser leurs données grâce à diverses techniques de cryptage.

Fonctionnalités principales :

Authentification et gestion des utilisateurs :

Connexion avec CAPTCHA : Protection contre les bots via un système CAPTCHA intégré.
Inscription sécurisée : Création de nouveaux comptes avec validation des données.
Gestion des rôles : Deux types d'utilisateurs sont pris en charge : admin et user.
Les admins peuvent :
Ajouter ou supprimer des utilisateurs.
Attribuer des rôles (admin ou user).
Envoyer des messages à d'autres utilisateurs.
Consulter les journaux d'activités (logs).
Interface utilisateur personnalisée :

Les admins et les users accèdent à des interfaces spécifiques selon leur rôle.
Fonctionnalités de cryptage :

Plusieurs algorithmes de cryptage sont intégrés pour protéger les données :
AES (Advanced Encryption Standard)
Cryptage d'image
Matrice de cryptage
Chiffrement César
Cryptage des messages avec KEK (Key Encryption Key) et DEK (Data Encryption Key) pour garantir la sécurité.
Un utilisateur peut consulter ses messages uniquement après avoir entré son mot de passe pour les décrypter.
Messagerie sécurisée :

Les utilisateurs peuvent envoyer des messages sécurisés entre eux.
Les messages sont chiffrés et nécessitent une authentification pour être déchiffrés.
Key Vault :

Les secrets, comme les clés de cryptage, sont stockés dans un Key Vault sécurisé.
Les utilisateurs peuvent y accéder en fournissant le nom du secret et leur mot de passe.
Logs et audit :

Les admins peuvent consulter les logs d'activité pour surveiller l'utilisation de la plateforme.
Résumé technique :
La plateforme met en œuvre des principes avancés de sécurité cloud, notamment l'utilisation de cryptographie asymétrique et symétrique, la gestion des identités, et le stockage sécurisé des secrets.
