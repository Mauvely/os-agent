# Helpers shared by make-remote.sh and make-remote-extra.sh. Needs env.sh sourced already.
export GNUPGHOME="$S0_ROOT/gpg"
repo="$S0_ROOT/repo"
b="$S0_ROOT/build"
arch=x86_64
rt=org.freedesktop.Platform/$arch/25.08
sdk=org.freedesktop.Sdk/$arch/25.08

remote_key() { gpg --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}'; }

export_dir() {  # <dir> <branch> [extra build-export flags]
  local dir="$1" branch="$2"; shift 2
  s0flatpak_raw build-export --no-update-summary --disable-fsync \
    --gpg-sign="$(remote_key)" --gpg-homedir="$GNUPGHOME" "$@" "$repo" "$dir" "$branch"
}

mkapp() {  # <id> <filesystems or empty>
  local id="$1" fs="$2" d="$b/$1"
  rm -rf "$d"; mkdir -p "$d/files/bin"
  cp "$S0_ROOT/bin/s0client" "$d/files/bin/"
  {
    printf '[Application]\nname=%s\nruntime=%s\nsdk=%s\ncommand=s0client\n' "$id" "$rt" "$sdk"
    [ -z "$fs" ] || printf '\n[Context]\nfilesystems=%s;\n' "$fs"
  } > "$d/metadata"
  s0flatpak_raw build-finish --no-inherit-permissions "$d" >/dev/null
  export_dir "$d" stable
}

# A runtime-kind extension: the files appear under the extension point's directory.
mkext() {  # <extension id> <branch> <parent app ref> <src:dest-in-files>...
  local id="$1" branch="$2" parent="$3" d="$b/$1" pair; shift 3
  rm -rf "$d"; mkdir -p "$d/files"
  for pair in "$@"; do
    mkdir -p "$d/files/$(dirname "${pair#*:}")"
    cp "${pair%%:*}" "$d/files/${pair#*:}"
  done
  printf '[Runtime]\nname=%s\n\n[ExtensionOf]\nref=%s\n' "$id" "$parent" > "$d/metadata"
  export_dir "$d" "$branch"
}

update_repo() { s0flatpak_raw build-update-repo --gpg-sign="$(remote_key)" --gpg-homedir="$GNUPGHOME" "$repo"; }
