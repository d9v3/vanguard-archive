GARDIEN for Linux — how to run it
=================================
Français : LISEZMOI.txt

The program: "gardien", in this folder. Any 64-bit distribution (x86_64), nothing to install.


1. THE EASIEST WAY

   Double-click "autorun.sh" at the root of the key: a terminal opens with the menu.
   GNOME also offers it when the key is plugged in ("Run software?").


2. IN A TERMINAL

   Open a terminal (Ctrl+Alt+T on most desktops) and type the path of the program, without first going
   into the key with "cd": on another computer, Gardien remounts the key read-only to protect it, which
   fails if a terminal is open in it.

     /run/media/$USER/GARDIEN/Linux/gardien     Arch, Fedora, openSUSE, Manjaro…
     /media/$USER/GARDIEN/Linux/gardien         Ubuntu, Debian, Mint, Pop!_OS…

   Where is the key mounted?   lsblk -o LABEL,MOUNTPOINT | grep GARDIEN
   Tip: type the start of the path, then the Tab key to complete it.


3. USEFUL COMMANDS

   Nothing after "gardien": the menu. Otherwise ("gardien" = the full path above):

     gardien full                 full check: this machine, then the network
     gardien full --text          same check, report as plain text (server without a screen)
     gardien fix                  check, then each fix shown and confirmed
     gardien audit                audit of this machine only
     gardien network              local network scan
     gardien update               updates: system, Flatpak, Snap, firmware…
     gardien repair               repairs: Internet, full disk, stuck updates…
     gardien clean --list         space to gain, deleting nothing
     gardien connection           connection test: ping, speed, bufferbloat
     gardien antivirus <folder>   scan a key, a disk or a folder
     gardien --help               every command (gardien <command> --help: the details)
     gardien --version            the version


4. GOOD TO KNOW

   - The terminal does not need root: a fix asks for your password (sudo) when you accept it, never
     before.
   - "Permission denied": the key is mounted without execute rights (noexec option). Copy the program,
     then run it:  cp /run/media/$USER/GARDIEN/Linux/gardien ~/ && ~/gardien
   - To install it on this computer: copy "gardien" to ~/.local/bin, then just type "gardien" in any
     terminal.
   - In French:  GARDIEN_LANG=fr /run/media/$USER/GARDIEN/Linux/gardien
   - Quit: q in the menu, or Ctrl+C.

Full guide (menu, key protection, language): README.txt at the root of the key.
