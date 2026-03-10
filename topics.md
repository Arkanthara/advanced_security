# Side Channel Attacks — Advanced Security

## 1. 🏆 Spectre (Spectre v1 & v2)

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **9/10** |
| 🛠️ Difficulté pratique | **8/10** |
| 🎯 Fun | **10/10** |
| 📅 Découverte | Janvier **2018** (Google Project Zero) |
| ⏳ Durée d'exposition | 1995–2018 (~23 ans sans le savoir) |
| ✅ Correctifs | Partiels (retpoline, microcode patches, isolation KPTI) |
| ⚠️ Encore exploitable ? | **Oui**, variants récents encore actifs (Spectre-v2 sur Linux 2024) |
| 📊 Systèmes vulnérables | ~**35–40%** des CPUs en production (vieux Intel/AMD non patchés) |

**Principe** : Exploite l'**exécution spéculative** du CPU. En forçant le processeur à exécuter du code "dans le futur" puis à l'annuler, les données transitent quand même par le cache — et sont lisibles via une attaque de timing.

> 💡 **Pourquoi c'est fun** : Tu peux lire la mémoire d'un autre processus, voire du kernel, depuis du JavaScript dans un navigateur. Le concept de "lire ce qui n'a pas encore été exécuté" est mind-blowing.

---

## 2. 🔥 Meltdown

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **8/10** |
| 🛠️ Difficulté pratique | **6/10** |
| 🎯 Fun | **9/10** |
| 📅 Découverte | Janvier **2018** (simultané avec Spectre) |
| ⏳ Durée d'exposition | ~1995–2018 |
| ✅ Correctifs | KPTI (Kernel Page Table Isolation) — très efficace |
| ⚠️ Encore exploitable ? | **Rarement** sur systèmes patchés, mais toujours possible sur systèmes embarqués/legacy |
| 📊 Systèmes vulnérables | ~**15–20%** (surtout vieux Intel pré-2019 non mis à jour) |

**Principe** : Exploite le fait que le CPU charge en mémoire des données **kernel** avant même de vérifier les permissions. En mesurant le timing du cache (Flush+Reload), on récupère ces données.

> 💡 **Pourquoi c'est fun** : PoC public disponible, résultats spectaculaires, et la démo de lecture de mémoire kernel en temps réel reste l'une des plus impressionnantes de l'histoire de la sécu.

---

## 3. ⚡ Flush+Reload / Prime+Probe

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **7/10** |
| 🛠️ Difficulté pratique | **7/10** |
| 🎯 Fun | **8/10** |
| 📅 Découverte | **2013** (Yarom & Falkner) |
| ⏳ Durée d'exposition | 2000–présent (toujours actif) |
| ✅ Correctifs | Aucun correctif matériel universel — mitigations logicielles partielles |
| ⚠️ Encore exploitable ? | **Oui**, base de la majorité des attaques cache modernes |
| 📊 Systèmes vulnérables | **~70%** (toute architecture avec cache L3 partagé) |

**Principe** : Technique de mesure du cache CPU. **Flush+Reload** : vider une ligne de cache, attendre, mesurer le temps de rechargement → si rapide, la victime a utilisé cette donnée. Sert de **primitive à presque toutes les attaques modernes**.

> 💡 **Pourquoi c'est fun** : C'est la brique de base. Comprendre Flush+Reload, c'est comprendre 80% des side-channel attacks modernes. Très pédagogique et implémentable en C en quelques heures.

---

## 4. 🔑 RSA Timing Attack (Kocher, 1996)

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **6/10** |
| 🛠️ Difficulté pratique | **5/10** |
| 🎯 Fun | **7/10** |
| 📅 Découverte | **1996** (Paul Kocher) |
| ⏳ Durée d'exposition | 1977–~2003 (implémentations non protégées) |
| ✅ Correctifs | Blinding RSA, constant-time implementations (OpenSSL depuis ~2003) |
| ⚠️ Encore exploitable ? | Sur **implémentations maison ou embarquées** non protégées — OUI |
| 📊 Systèmes vulnérables | ~**5–10%** (IoT, smartcards legacy, code custom) |

**Principe** : En mesurant le **temps d'exécution** du déchiffrement RSA sur des milliers de requêtes, on peut reconstruire la clé privée bit par bit grâce aux variations de timing de l'exponentiation modulaire.

> 💡 **Pourquoi c'est fun** : L'attaque originale qui a tout lancé. Le paper de Kocher est une lecture obligatoire. Implémenter ça sur une smartcard ou un Arduino, c'est ultra satisfaisant.

---

## 5. 🎭 Rowhammer

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **7/10** |
| 🛠️ Difficulté pratique | **8/10** |
| 🎯 Fun | **9/10** |
| 📅 Découverte | **2014** (Kim et al., Google Project Zero 2015) |
| ⏳ Durée d'exposition | ~2010–présent |
| ✅ Correctifs | TRR (Target Row Refresh), ECC RAM, LPDDR4X mitigations — **incomplets** |
| ⚠️ Encore exploitable ? | **Oui** — Half-Double (2021), DRAM Still Hammering (2023) |
| 📊 Systèmes vulnérables | ~**40–50%** des DRAM non-ECC grand public |

**Principe** : En accédant répétitivement à des lignes mémoire adjacentes, on provoque des **bit flips** dans la RAM via interférence électromagnétique physique. Peut servir à une **escalade de privilèges**.

> 💡 **Pourquoi c'est fun** : C'est une attaque **purement physique** sur le hardware. Faire flip un bit en RAM pour obtenir root, c'est de la magie noire. Des exploits fonctionnent depuis le navigateur (JS Rowhammer).

---

## 6. 🌡️ Power Analysis (SPA/DPA)

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **8/10** |
| 🛠️ Difficulté pratique | **9/10** |
| 🎯 Fun | **8/10** |
| 📅 Découverte | **1998** (Paul Kocher — DPA) |
| ⏳ Durée d'exposition | 1980–présent (toujours actif sur non-protégé) |
| ✅ Correctifs | Masking, randomisation, hardware shields |
| ⚠️ Encore exploitable ? | **Oui**, sur cartes à puce, IoT, HSM bas de gamme |
| 📊 Systèmes vulnérables | ~**30%** des devices embarqués sans countermeasures |

**Principe** : Mesurer la **consommation électrique** d'un circuit pendant un chiffrement AES/RSA. Les variations de puissance corrèlent avec les données traitées → reconstruction de la clé.

> 💡 **Pourquoi c'est fun** : Nécessite un oscilloscope et une cible physique (Arduino, smartcard). Très hands-on, résultats visuellement impressionnants. Parfait pour un labo de sécu hardware.

---

## 7. 🔊 Acoustic Cryptanalysis

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **9/10** |
| 🛠️ Difficulté pratique | **10/10** |
| 🎯 Fun | **10/10** |
| 📅 Découverte | **2004** (Shamir & Tromer), **2013** (Genkin et al. — RSA via son) |
| ⏳ Durée d'exposition | 2004–~2015 (GnuPG patché en 2014) |
| ✅ Correctifs | Randomisation des opérations RSA dans GnuPG |
| ⚠️ Encore exploitable ? | **Théoriquement oui** sur implémentations non protégées |
| 📊 Systèmes vulnérables | < **1%** (très ciblé, très spécifique) |

**Principe** : Les composants électroniques émettent des sons haute fréquence pendant les calculs. En enregistrant avec un micro à 4cm d'un laptop, Genkin et al. ont extrait une clé RSA-4096 en **1 heure**.

> 💡 **Pourquoi c'est fun** : **Extraire une clé RSA avec un téléphone posé à côté d'un laptop**. C'est l'attaque la plus "cinéma" qui soit, et elle est réelle et documentée scientifiquement.

---

## 8. 🌐 NetSpectre

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **10/10** |
| 🛠️ Difficulté pratique | **10/10** |
| 🎯 Fun | **7/10** |
| 📅 Découverte | **2018** (Schwarz et al.) |
| ⏳ Durée d'exposition | 2018–présent (mitigations partielles) |
| ✅ Correctifs | Même patches que Spectre + réduction précision timers réseau |
| ⚠️ Encore exploitable ? | Très difficile en pratique mais théoriquement oui |
| 📊 Systèmes vulnérables | ~**10–15%** (serveurs non patchés) |

**Principe** : Variante de Spectre exploitable **à distance via le réseau**, sans code local. En mesurant les temps de réponse réseau, on infère l'état du cache du serveur distant.

> 💡 **Pourquoi c'est fun** : L'idée même qu'on peut faire une attaque Spectre **sans accès physique ni code exécuté sur la machine** est conceptuellement fascinante.


# 🔐 Side Channel Attacks — Cryptographic Oracles & Beyond

---

## 1. 🧱 Padding Oracle Attack (Vaudenay)

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **6/10** |
| 🛠️ Difficulté pratique | **4/10** |
| 🎯 Fun | **9/10** |
| 📅 Découverte | **2002** (Serge Vaudenay) |
| ⏳ Durée d'exposition | 2002–présent (implémentations vulnérables) |
| ✅ Correctifs | Encrypt-then-MAC, AEAD (AES-GCM), padding constant-time |
| ⚠️ Encore exploitable ? | **Oui** — apps legacy, frameworks mal configurés |
| 📊 Systèmes vulnérables | ~**15–20%** des apps web utilisant CBC sans AEAD |

**Principe** : En envoyant des ciphertexts modifiés à un serveur et en observant si l'erreur retournée est `"padding invalide"` ou `"déchiffrement invalide"`, on crée un **oracle** qui permet de déchiffrer **n'importe quel message CBC bloc par bloc**, sans connaître la clé.

> 💡 **Pourquoi c'est fun** : Le concept d'**oracle** est central à toute la crypto moderne. Avec `padbuster` ou un script Python basique, tu déchiffres un cookie de session en ~128 requêtes. Résultat garanti, démo explosive en cours.

---

## 2. 👾 Bleichenbacher Attack (RSA PKCS#1 v1.5)

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **8/10** |
| 🛠️ Difficulté pratique | **6/10** |
| 🎯 Fun | **8/10** |
| 📅 Découverte | **1998** (Daniel Bleichenbacher — Bell Labs) |
| ⏳ Durée d'exposition | 1998–présent (variants toujours actifs) |
| ✅ Correctifs | RSA-OAEP, TLS 1.3 (suppression RSA key exchange) |
| ⚠️ Encore exploitable ? | **Oui** — ROBOT (2017) a prouvé que des milliers de serveurs HTTPS étaient encore vuln. |
| 📊 Systèmes vulnérables | ~**8–12%** des serveurs HTTPS (pré-TLS 1.3) |

**Principe** : En envoyant des ciphertexts RSA modifiés à un serveur TLS et en observant s'il répond `"PKCS conformant"` ou non, on adapte l'attaque statistiquement pour retrouver le plaintext RSA en ~1 million de requêtes.

> 💡 **Pourquoi c'est fun** : Le paper original est un chef-d'œuvre de mathématiques appliquées. Et ROBOT (2017) a montré que **Facebook, PayPal, Cisco** étaient encore vulnérables 19 ans plus tard. La honte universelle.

---

## 3. 🤖 ROBOT Attack

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **8/10** |
| 🛠️ Difficulté pratique | **5/10** |
| 🎯 Fun | **8/10** |
| 📅 Découverte | **Décembre 2017** (Böck, Somorovsky, Young) |
| ⏳ Durée d'exposition | 1998–2017 (implémentations non corrigées) |
| ✅ Correctifs | Patchs constructeurs, migration TLS 1.3 |
| ⚠️ Encore exploitable ? | **Sur serveurs legacy non patchés** — oui |
| 📊 Systèmes vulnérables | ~**5%** du top million Alexa lors de la découverte |

**Principe** : Même attaque que Bleichenbacher, mais automatisée et appliquée à des implémentations modernes (F5, Citrix, Cisco...) qui avaient **réintroduit la vulnérabilité** dans leurs stacks TLS.

> 💡 **Pourquoi c'est fun** : Le scanner est public (`robot-detect`). Tu peux tester n'importe quel serveur HTTPS en quelques secondes. Le nom est parfait : **R**eturn **O**f **B**leichenbacher's **O**racle **T**hreat.

---

## 4. 🐩 POODLE

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **6/10** |
| 🛠️ Difficulté pratique | **6/10** |
| 🎯 Fun | **7/10** |
| 📅 Découverte | **Octobre 2014** (Möller, Duong, Kotowicz — Google) |
| ⏳ Durée d'exposition | 1996 (SSL 3.0)–2014 |
| ✅ Correctifs | Désactivation SSLv3 universelle |
| ⚠️ Encore exploitable ? | **Presque jamais** — SSLv3 mort. Variant TLS-POODLE sur certains serveurs |
| 📊 Systèmes vulnérables | < **1%** (SSLv3 activé = négligence grave) |

**Principe** : SSLv3 ne vérifie pas le contenu du padding CBC, seulement sa longueur. En forçant un **downgrade** de TLS vers SSLv3 via un MITM, puis en exploitant le padding oracle, on déchiffre des cookies de session.

> 💡 **Pourquoi c'est fun** : Le nom (**P**adding **O**racle **O**n **D**owngraded **L**egacy **E**ncryption) et le logo du caniche. Plus sérieusement, c'est un excellent exemple d'**attaque en downgrade** combinée à un oracle — deux concepts en un.

---

## 5. ⏱️ Lucky Thirteen

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **8/10** |
| 🛠️ Difficulté pratique | **8/10** |
| 🎯 Fun | **7/10** |
| 📅 Découverte | **Février 2013** (Al Fardan & Paterson) |
| ⏳ Durée d'exposition | 2002 (TLS 1.0/1.1 CBC)–2013 |
| ✅ Correctifs | Constant-time MAC, migration vers AEAD |
| ⚠️ Encore exploitable ? | Sur **implémentations TLS legacy non patchées** |
| 📊 Systèmes vulnérables | ~**10%** (OpenSSL < 1.0.1e, GnuTLS legacy) |

**Principe** : En TLS-CBC, la vérification du MAC prend **plus ou moins de temps** selon la longueur du padding. Différence de **quelques nanosecondes** — mais suffisante pour reconstituer un oracle de padding via mesures statistiques massives.

> 💡 **Pourquoi c'est fun** : C'est une attaque sur **13 nanosecondes de différence**. La précision requise est absurde, et pourtant ça marche. Un monument de la cryptographie appliquée.

---

## 6. 💨 CRIME & BREACH

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **7/10** |
| 🛠️ Difficulté pratique | **6/10** |
| 🎯 Fun | **9/10** |
| 📅 Découverte | **2012** (CRIME - Duong & Rizzo) / **2013** (BREACH - Gluck et al.) |
| ⏳ Durée d'exposition | 2012–présent (BREACH toujours actif) |
| ✅ Correctifs | CRIME : désactivation compression TLS. BREACH : **aucun fix universel** |
| ⚠️ Encore exploitable ? | **BREACH : OUI** — toujours actif sur HTTP compression |
| 📊 Systèmes vulnérables | ~**50%** des sites HTTPS avec compression HTTP activée |

**Principe** : La **compression révèle des informations** sur les données. Si un attaquant peut injecter du texte dans une requête compressée+chiffrée et observer la taille du ciphertext, il peut deviner le contenu secret (ex: token CSRF) **caractère par caractère**.

> 💡 **Pourquoi c'est fun** : BREACH n'a **toujours pas de fix propre** en 2026. La compression et le chiffrement sont fondamentalement incompatibles — un résultat théorique élégant avec des conséquences très réelles.

---

## 7. 🌊 DROWN

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **8/10** |
| 🛠️ Difficulté pratique | **6/10** |
| 🎯 Fun | **7/10** |
| 📅 Découverte | **Mars 2016** (Aviram et al.) |
| ⏳ Durée d'exposition | 1995 (SSLv2)–2016 |
| ✅ Correctifs | Désactivation SSLv2, séparation des clés RSA |
| ⚠️ Encore exploitable ? | **Rare** — SSLv2 quasi-éteint |
| 📊 Systèmes vulnérables | **33% des serveurs HTTPS** lors de la découverte (2016) |

**Principe** : Si un serveur supporte encore SSLv2 **avec la même clé RSA** que son HTTPS moderne, SSLv2 agit comme oracle Bleichenbacher dégradé. On attaque SSLv2 pour **déchiffrer des sessions TLS modernes**.

> 💡 **Pourquoi c'est fun** : Un tiers d'internet vulnérable. Et l'idée d'utiliser un protocole de 1995 pour casser du TLS 1.2 moderne est une leçon d'humilité sur le **legacy code**.

---

## 8. 🦋 Hertzbleed

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **9/10** |
| 🛠️ Difficulté pratique | **8/10** |
| 🎯 Fun | **8/10** |
| 📅 Découverte | **Juin 2022** (Wang et al. — UT Austin) |
| ⏳ Durée d'exposition | ~2015–2022 (DVFS sur CPUs modernes) |
| ✅ Correctifs | Désactivation du boost fréquence, constant-time crypto — **partiels** |
| ⚠️ Encore exploitable ? | **Oui** sur CPUs Intel/AMD avec DVFS activé |
| 📊 Systèmes vulnérables | ~**60–70%** des CPUs modernes grand public |

**Principe** : Le **Dynamic Voltage and Frequency Scaling (DVFS)** fait varier la fréquence du CPU selon la charge. Ces variations de fréquence créent des variations de timing mesurables **à distance**, même via réseau — transformant la fréquence CPU en oracle cryptographique sur SIKE/Kyber.

> 💡 **Pourquoi c'est fun** : Intel et AMD ont répondu que ce n'était **pas un bug mais une feature**. C'est une attaque sur les mécanismes d'économie d'énergie — une nouvelle frontière des side-channels.

---

## 9. ⚡ PLATYPUS

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **8/10** |
| 🛠️ Difficulté pratique | **7/10** |
| 🎯 Fun | **8/10** |
| 📅 Découverte | **Novembre 2020** (Lipp et al. — TU Graz) |
| ⏳ Durée d'exposition | 2011–2020 (interface RAPL Intel) |
| ✅ Correctifs | Restriction accès RAPL, patches Linux/Windows |
| ⚠️ Encore exploitable ? | **Partiellement** sur systèmes non patchés |
| 📊 Systèmes vulnérables | ~**25%** (Intel Sandy Bridge à Ice Lake) |

**Principe** : Intel expose une interface logicielle **RAPL** (Running Average Power Limit) lisible **sans privilèges** sous Linux. En mesurant la consommation énergétique via RAPL pendant des opérations AES dans SGX, on extrait la clé — une DPA attack entièrement logicielle.

> 💡 **Pourquoi c'est fun** : C'est la **Power Analysis Attack sans oscilloscope** — 100% logiciel, depuis un process user-space. La même attaque que les smartcards, mais sur un laptop.

---

## 10. 🧟 ZombieLoad / RIDL / Fallout

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **9/10** |
| 🛠️ Difficulté pratique | **7/10** |
| 🎯 Fun | **8/10** |
| 📅 Découverte | **Mai 2019** (TU Graz, VU Amsterdam, KU Leuven) |
| ⏳ Durée d'exposition | ~2012–2019 |
| ✅ Correctifs | MDS mitigations microcode, MDS clear buffers, hyperthreading désactivé |
| ⚠️ Encore exploitable ? | **Oui** sur CPUs pré-2020 non patchés |
| 📊 Systèmes vulnérables | ~**30%** (Intel Skylake et antérieur) |

**Principe** : Exploite les **buffers internes du CPU** (Line Fill Buffer, Store Buffer, Load Ports). En lisant des données depuis ces buffers via l'exécution spéculative, on récupère des données d'**autres processus, VMs, ou du SGX** — cross-VM en cloud compris.

> 💡 **Pourquoi c'est fun** : Lire des données d'une autre VM sur le même hyperviseur AWS. Le cauchemar du cloud computing. La famille MDS est la suite logique et plus puissante de Meltdown.

---

## 11. 🐅 Foreshadow (L1TF)

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **9/10** |
| 🛠️ Difficulté pratique | **7/10** |
| 🎯 Fun | **7/10** |
| 📅 Découverte | **Août 2018** (Van Bulck et al.) |
| ⏳ Durée d'exposition | 2015 (SGX intro)–2018 |
| ✅ Correctifs | Microcode patches, hypervisor fixes |
| ⚠️ Encore exploitable ? | **Partiellement** sans hyperthreading désactivé |
| 📊 Systèmes vulnérables | ~**20%** (Intel avec SGX, Skylake–Kaby Lake) |

**Principe** : Exploite le L1 Data Cache pour lire la **mémoire physique entière**, y compris les enclaves SGX (le "coffre-fort" d'Intel). Brise la promesse fondamentale de SGX : l'isolation même face à un OS compromis.

> 💡 **Pourquoi c'est fun** : SGX est censé être **inviolable même par le kernel**. Foreshadow a démontré que c'est faux. Une humiliation totale pour Intel et leur marketing.

---

## 12. 🔀 PortSmash

| Attribut | Détail |
|---|---|
| 🧠 Difficulté théorique | **8/10** |
| 🛠️ Difficulté pratique | **8/10** |
| 🎯 Fun | **7/10** |
| 📅 Découverte | **Octobre 2018** (Aldaya et al.) |
| ⏳ Durée d'exposition | ~2002 (Hyper-Threading intro)–2018 |
| ✅ Correctifs | Désactivation SMT/Hyper-Threading |
| ⚠️ Encore exploitable ? | **Oui** si HT activé et pas de OS-level isolation |
| 📊 Systèmes vulnérables | ~**40%** (tout CPU avec SMT/HT activé) |

**Principe** : Deux threads sur le **même core physique** (via HyperThreading) partagent les **execution ports**. En mesurant la contention sur ces ports depuis un thread malveillant, on reconstruit le flux d'exécution du thread victime — et on extrait une clé OpenSSL P-384.

> 💡 **Pourquoi c'est fun** : Une attaque sur l'**architecture même du parallélisme**. Et le fix officiel — désactiver l'hyperthreading — coûte 30–50% de performance. Choisir entre sécurité et perf, en 2018.

---

## 📊 Tableau récapitulatif

| Attaque | 🧠 Théorie | 🛠️ Pratique | 🎯 Fun | Encore active ? | % Vulnérables |
|---|---|---|---|---|---|
| Spectre | 9/10 | 8/10 | 10/10 | ✅ Oui | ~35-40% |
| Meltdown | 8/10 | 6/10 | 9/10 | ⚠️ Partiel | ~15-20% |
| Flush+Reload | 7/10 | 7/10 | 8/10 | ✅ Oui | ~70% |
| RSA Timing | 6/10 | 5/10 | 7/10 | ⚠️ IoT/legacy | ~5-10% |
| Rowhammer | 7/10 | 8/10 | 9/10 | ✅ Oui | ~40-50% |
| Power Analysis | 8/10 | 9/10 | 8/10 | ✅ Oui | ~30% |
| Acoustic | 9/10 | 10/10 | 10/10 | ⚠️ Rare | <1% |
| NetSpectre | 10/10 | 10/10 | 7/10 | ⚠️ Partiel | ~10-15% |
| Padding Oracle | 6/10 | 4/10 | 9/10 | ✅ Oui (legacy) | ~15-20% |
| Bleichenbacher | 8/10 | 6/10 | 8/10 | ✅ Variants actifs | ~8-12% |
| ROBOT | 8/10 | 5/10 | 8/10 | ⚠️ Legacy servers | ~5% |
| POODLE | 6/10 | 6/10 | 7/10 | ❌ Quasi-mort | <1% |
| Lucky Thirteen | 8/10 | 8/10 | 7/10 | ⚠️ Legacy TLS | ~10% |
| CRIME/BREACH | 7/10 | 6/10 | 9/10 | ✅ BREACH actif | ~50% |
| DROWN | 8/10 | 6/10 | 7/10 | ❌ Rare | <2% |
| Hertzbleed | 9/10 | 8/10 | 8/10 | ✅ Oui | ~60-70% |
| PLATYPUS | 8/10 | 7/10 | 8/10 | ⚠️ Partiel | ~25% |
| ZombieLoad/RIDL | 9/10 | 7/10 | 8/10 | ⚠️ Non patchés | ~30% |
| Foreshadow | 9/10 | 7/10 | 7/10 | ⚠️ Partiel | ~20% |
| PortSmash | 8/10 | 8/10 | 7/10 | ✅ Si HT actif | ~40% |