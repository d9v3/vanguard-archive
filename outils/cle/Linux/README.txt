VANGUARD for Linux — how to run it
=================================
Français : LISEZMOI.txt

The program: "vanguard", in this folder. Any 64-bit distribution (x86_64), nothing to install.


1. THE EASIEST WAY

   Double-click "autorun.sh" at the root of the key: a terminal opens with the menu.
   GNOME also offers it when the key is plugged in ("Run software?").


2. IN A TERMINAL

   Open a terminal (Ctrl+Alt+T on most desktops) and type the path of the program, without first going
   into the key with "cd": on another computer, Vanguard remounts the key read-only to protect it, which
   fails if a terminal is open in it.

     /run/media/$USER/VANGUARD/Linux/vanguard     Arch, Fedora, openSUSE, Manjaro…
     /media/$USER/VANGUARD/Linux/vanguard         Ubuntu, Debian, Mint, Pop!_OS…

   Where is the key mounted?   lsblk -o LABEL,MOUNTPOINT | grep VANGUARD
   Tip: type the start of the path, then the Tab key to complete it.


3. USEFUL COMMANDS

   Nothing after "vanguard": the menu. Otherwise ("vanguard" = the full path above):

     vanguard full                 full check: this machine, then the network
     vanguard full --text          same check, report as plain text (server without a screen)
     vanguard fix                  check, then each fix shown and confirmed
     vanguard audit                audit of this machine only
     vanguard network              local network scan
     vanguard update               updates: system, Flatpak, Snap, firmware…
     vanguard repair               repairs: Internet, full disk, stuck updates…
     vanguard clean --list         space to gain, deleting nothing
     vanguard connection           connection test: ping, speed, bufferbloat
     vanguard antivirus <folder>   scan a key, a disk or a folder
     vanguard --help               every command (vanguard <command> --help: the details)
     vanguard --version            the version


4. GOOD TO KNOW

   - The terminal does not need root: a fix asks for your password (sudo) when you accept it, never
     before.
   - "Permission denied": the key is mounted without execute rights (noexec option). Copy the program,
     then run it:  cp /run/media/$USER/VANGUARD/Linux/vanguard ~/ && ~/vanguard
   - To install it on this computer: copy "vanguard" to ~/.local/bin, then just type "vanguard" in any
     terminal.
   - In French:  VANGUARD_LANG=fr /run/media/$USER/VANGUARD/Linux/vanguard
   - Quit: q in the menu, or Ctrl+C.


5. INSTALLING LINUX FROM THE KEY

   Boot the computer from the key (boot menu key: F12, F11, F8 or Esc depending on the PC), then pick
   from the Ventoy menu. Debian, Fedora and Arch install over the Internet (cable or Wi-Fi).
   - Omarchy: pick Arch Linux, join the Wi-Fi (iwctl, then "station wlan0 connect <network>"), run
     archinstall (LUKS-encrypted disk, btrfs, Limine boot loader, pipewire audio, network "copy ISO
     network config"), reboot, log in, then type:
       curl -fsSL https://omarchy.org/install | bash
     Official guide: https://learn.omacom.io/2/the-omarchy-manual/96/manual-installation
   - The images update themselves when the key is plugged into the computer that prepares it.

Full guide (menu, key protection, language): README.txt at the root of the key.
