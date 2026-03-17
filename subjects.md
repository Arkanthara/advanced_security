# Sujets des documents (triés par difficulté d'implémentation + test)

Objectif: classer les papiers du dossier `documents/` du plus simple au plus difficile pour un mini-projet d'advanced security fait from scratch.

Echelle utilisée:
- Difficulté: 1 (très simple) -> 5 (très difficile)
- Critères: complexité math/code, effort d'environnement de test, volume de données à collecter, reproductibilité.

## 1) Timing attacks génériques sur RSA/DH/DSS
- Fichier: `documents/TimingAttacks.pdf`
- Difficulté: **1/5**
- Explication simple: papier fondateur (Kocher, 1996) montrant qu'un temps d'exécution variable peut fuiter des infos sur les secrets cryptographiques.
- Pourquoi c'est le plus simple: très pédagogique, facile à reproduire en local avec un code naïf qui fait des branches selon les bits de clé.
- Mini-projet possible: implémenter une exponentiation modulaire non constante, mesurer les temps sur beaucoup de requêtes, puis montrer qu'un secret partiel est corrélé au timing.

## 2) Fermat factorization sur clés RSA faibles
- Fichier: `documents/2023-026.pdf`
- Difficulté: **1.5/5**
- Explication simple: si `p` et `q` sont trop proches dans RSA, la factorisation de Fermat casse rapidement la clé privée.
- Pourquoi c'est simple: l'attaque est directe, peu de dépendances, testable offline sur des clés volontairement mal générées.
- Mini-projet possible: générer des clés RSA vulnérables (`|p-q|` petit), implémenter Fermat from scratch, comparer temps de factorisation vs clés saines.

## 3) Timing de frappe SSH (keystroke timing)
- Fichier: `documents/ssh-use01.pdf`
- Difficulté: **2/5**
- Explication simple: même avec chiffrement SSH, la taille des paquets et l'intervalle entre frappes peuvent révéler des infos (longueur de mot de passe, patterns de saisie).
- Pourquoi c'est accessible: pas besoin de casser la crypto, surtout de l'analyse statistique temporelle.
- Mini-projet possible: simuler des sessions de frappe, extraire les intervalles inter-touches, entraîner un classifieur simple pour prédire longueur ou classes de mots.

## 4) Cache-timing sur AES
- Fichier: `documents/aes_timing.pdf`
- Difficulté: **3/5**
- Explication simple: implémentations AES à base de tables (T-tables/S-box en mémoire) produisent des timings dépendants du cache, exploitables pour retrouver la clé.
- Pourquoi difficulté moyenne: nécessite beaucoup de mesures propres et une implémentation de collecte/filtrage des timings.
- Mini-projet possible: serveur AES vulnérable local, client qui envoie plaintexts choisis, collecte des timings, attaque statistique sur des octets de clé.

## 5) Lucky Thirteen (TLS/DTLS CBC timing)
- Fichier: `documents/TLStiming.pdf`
- Difficulté: **4/5**
- Explication simple: de minuscules différences de temps dans le traitement CBC+MAC en TLS peuvent créer un oracle permettant de récupérer du plaintext.
- Pourquoi c'est difficile: signal timing très faible, bruit réseau important, besoin d'un protocole TLS précis.
- Mini-projet possible: reproduire une version simplifiée en local (oracle CBC artificiel) avant d'approcher une stack TLS réelle.

## 6) Logjam et faiblesse Diffie-Hellman en pratique
- Fichier: `documents/imperfect-forward-secrecy.pdf`
- Difficulté: **4.5/5**
- Explication simple: downgrade vers des groupes DH export/faibles; avec précomputation, certaines connexions TLS deviennent cassables.
- Pourquoi très difficile: partie algorithmes de log discret + précomputation coûteuse + setup protocolaire réaliste.
- Mini-projet possible: version réduite sur petits groupes DH pour démontrer le principe de downgrade et de résolution plus rapide après précomputation.

## 7) Revue avancée d'attaques AES (SCA, fautes, ML, quantique)
- Fichier: `documents/AdvanceattacksonAESAcomprehensivereviewofsidechannel.pdf`
- Difficulté: **5/5**
- Explication simple: survey large couvrant plusieurs familles d'attaques (side-channel, fault injection, machine learning, perspectives quantiques).
- Pourquoi le plus dur from scratch: ce n'est pas une seule attaque; il faut choisir un sous-sujet, et beaucoup de variantes demandent matériel spécifique ou dataset massif.
- Mini-projet possible: prendre une seule sous-partie (ex: CPA sur AES logiciel) au lieu de vouloir couvrir toute la revue.

---

## Ordre recommandé pour un petit projet (pratique)

1. `TimingAttacks.pdf`
2. `2023-026.pdf`
3. `ssh-use01.pdf`
4. `aes_timing.pdf`
5. `TLStiming.pdf`
6. `imperfect-forward-secrecy.pdf`
7. `AdvanceattacksonAESAcomprehensivereviewofsidechannel.pdf`

## Proposition de trajectoire en 3 étapes

1. Démarrer avec `TimingAttacks.pdf` + `2023-026.pdf` pour des PoC rapides et fiables en local.
2. Passer à `ssh-use01.pdf` + `aes_timing.pdf` pour introduire mesures réelles et statistiques.
3. Finir avec `TLStiming.pdf` et `imperfect-forward-secrecy.pdf` si tu veux un challenge protocolaire plus proche du monde réel.

---

## Projet concret proposé (version mini mais solide)

Idée: faire un petit labo reproductible en 2 modules, avec une logique "attaque -> mesure -> preuve -> mitigation".

### Module A: Timing attack pédagogique (inspiré Kocher)

- But: montrer qu'une implémentation non constante fuit de l'information via le temps.
- Ce que tu codes:
	- Un service local (ou script) qui calcule une opération crypto simplifiée avec branches dépendantes du secret.
	- Un collecteur qui envoie beaucoup d'entrées et mesure les temps.
	- Un analyseur statistique (corrélation, moyenne par classe d'entrée) pour retrouver des bits du secret.
- Démo attendue:
	- Graphique des timings (secret connu pour validation).
	- Taux de récupération du secret partiel (ex: premiers bits correctement devinés).
	- Version "corrigée" (constant-time) qui réduit la fuite.

### Module B: RSA faible + factorisation de Fermat

- But: montrer qu'une mauvaise génération de clés RSA casse la sécurité, même sans side-channel.
- Ce que tu codes:
	- Générateur de clés de test avec deux modes:
		- mode vulnérable: `p` et `q` volontairement proches.
		- mode sain: `p` et `q` bien espacés/aléatoires.
	- Implémentation Fermat from scratch.
	- Script benchmark qui compare le temps de factorisation selon la qualité des clés.
- Démo attendue:
	- Sur clés vulnérables: factorisation rapide.
	- Sur clés saines: factorisation non pratique dans le budget de temps fixé.
	- Tableau final "distance |p-q| vs temps d'attaque".

## Ce que le projet doit contenir au minimum

1. Code d'attaque reproductible.
2. Données de mesure sauvegardées (CSV/JSON).
3. Script d'analyse qui produit les chiffres/graphes.
4. Une mitigation implémentée et comparée au cas vulnérable.
5. Une conclusion factuelle: quand l'attaque marche, quand elle échoue, pourquoi.

## Plan d'implémentation court (7 jours)

1. J1: squelette du repo + scripts utilitaires + format des données.
2. J2-J3: Module A (version vulnérable + collecte timings).
3. J4: analyse statistique + première récupération de secret.
4. J5: version mitigée constant-time + comparaison.
5. J6: Module B (génération RSA test + Fermat + benchmark).
6. J7: rapport court + graphiques + résultats consolidés.

## Comment tester proprement

- Répéter chaque expérience plusieurs fois (au moins 20 runs) pour lisser le bruit.
- Fixer des seeds aléatoires pour rendre les tests comparables.
- Isoler les métriques:
	- succès de récupération (accuracy ou taux de bits corrects),
	- temps total d'attaque,
	- variance des mesures.
- Définir un critère de succès clair:
	- Module A: "au moins X bits récupérés avec p-value < seuil".
	- Module B: "clés vulnérables cassées sous T secondes, clés saines non cassées sous T secondes".

## Stack minimale avec uv

- Base: Python pur + `uv`.
- Dépendances utiles: `numpy`, `pandas`, `matplotlib`, éventuellement `scipy`.
- Exemple d'exécution sans venv manuel:
	- `uv run --with numpy --with pandas --with matplotlib python scripts/run_all.py`

## Résultat final attendu (niveau portfolio)

- Un README qui raconte la chaîne complète: hypothèse, attaque, résultats, mitigation.
- 2 PoC exécutables en une commande.
- 1 dossier de résultats avec figures et tableaux.
- 1 section "limitations" (bruit machine, simplifications, non-transposabilité directe en production).
