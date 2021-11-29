

Pour compiler le programme: 
gcc -o ransom ransom.c ransomlib.c -lcrypto

Pour lancer un serveur qui écoute pour récupérer la clé (le numéro de port au choix)
nc -lu -v -p 8888 

Le dossier "important" contient une série de dossiers et fichiers sur lesquel vous pouvez tester votre programme. 

