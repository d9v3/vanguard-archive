GARDIEN for macOS — how to run it
=================================
Français : LISEZMOI.txt

The program: "gardien", in this folder. macOS 12 Monterey and later, Apple Silicon (M1, M2…) and
Intel Macs, nothing to install.


1. THE EASIEST WAY

   Double-click "Lancer Gardien.command" at the root of the key: Terminal opens with the menu.


2. IN TERMINAL

   Open Terminal (Cmd+Space, type "Terminal", Enter; or Applications > Utilities) and type the path of
   the program, without first going into the key with "cd": on another Mac, Gardien remounts the key
   read-only to protect it, which fails if Terminal is open in it.

     /Volumes/GARDIEN/macOS/gardien

   Tips: type "/Volumes/GA" then the Tab key to complete; or drag the "gardien" file from the Finder
   into the Terminal window, then Enter.


3. USEFUL COMMANDS

   Nothing after "gardien": the menu. Otherwise ("gardien" = /Volumes/GARDIEN/macOS/gardien):

     gardien full                 full check: this Mac, then the network
     gardien full --text          same check, report as plain text
     gardien fix                  check, then each fix shown and confirmed
     gardien audit                audit of this Mac only
     gardien network              local network scan
     gardien update               updates: macOS, Homebrew, App Store…
     gardien repair               repairs: Internet, DNS, full disk…
     gardien clean --list         space to gain, deleting nothing
     gardien connection           connection test: ping, speed, bufferbloat
     gardien antivirus <folder>   scan a key, a disk or a folder (ClamAV)
     gardien --help               every command (gardien <command> --help: the details)
     gardien --version            the version


4. GOOD TO KNOW

   - A fix asks for your session password (sudo) when you accept it, never before.
   - Started from the key, Gardien opens without a warning. Copied from the Internet or by AirDrop,
     macOS blocks it ("unidentified developer"): in Terminal, xattr -d com.apple.quarantine gardien, or
     right-click > Open in the Finder.
   - Antivirus (ClamAV), software and gaming go through Homebrew, offered if it is missing.
   - In French:  GARDIEN_LANG=fr /Volumes/GARDIEN/macOS/gardien
   - Quit: q in the menu, or Ctrl+C.

Full guide (menu, key protection, language): README.txt at the root of the key.
