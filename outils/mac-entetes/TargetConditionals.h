/* Pour clippy sur les cibles Mac depuis Linux, sans les outils d'Apple (outils/verifier.sh, CI) : ring, le chiffrement
 * de TLS du client HTTPS, ne lit dans cet en-tête que le système visé. Jamais assemblé dans un programme livré : le
 * vrai Mac (macos.yml) compile avec les en-têtes d'Apple. */
#define TARGET_OS_MAC 1
#define TARGET_OS_OSX 1
#define TARGET_OS_IPHONE 0
#define TARGET_OS_IOS 0
#define TARGET_OS_TV 0
#define TARGET_OS_WATCH 0
#define TARGET_OS_VISION 0
#define TARGET_OS_SIMULATOR 0
