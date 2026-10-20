/* Pour clippy sur les cibles Mac depuis Linux, sans les outils d'Apple (outils/verifier.sh, CI) : wasmtime, le moteur
 * de YARA-X, compile un petit fichier C (helpers.c) qui ne prend que NULL dans stdlib.h. Ce fichier n'est jamais
 * assemblé dans un programme livré : le vrai Mac (macos.yml) compile avec les en-têtes d'Apple. */
#include <stddef.h>
