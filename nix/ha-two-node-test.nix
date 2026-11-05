{ pkgs, self }:
import ./ha-pair-test.nix { inherit pkgs self; twoNode = true; }
