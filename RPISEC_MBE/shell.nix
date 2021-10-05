with import <nixpkgs> {};

let
  customPython = pkgs.python39.buildEnv.override {
    extraLibs = [ pkgs.python39Packages.ipython pkgs.python39Packages.pwntools ];
  };
  bu6pwn = with python39Packages; buildPythonPackage rec {
    name = "bu6pwn";
    version="1.1";
    src = fetchFromGitHub {
      owner = "bu6hunt3r";
      repo="${name}";
      rev="ebad87111d398beb2abe05084d579507650ffb89";
      sha256="16lalm0id13qmxwnqjy3m0y7sndycxmkwqvphpp0qqrmb73gpz5p";
    };
  doCheck = false;
  };
in
mkShell {
  buildInputs = with python39Packages; [ setuptools sshpass customPython bu6pwn ];
}
