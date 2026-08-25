#!/usr/bin/env sh

yq --yaml-fix-merge-anchor-to-spec 'explode(.)' readpe.yaml > tmp.readpe.yaml

crazy-complete bash tmp.readpe.yaml > readpe.bash
crazy-complete fish tmp.readpe.yaml > readpe.fsh
crazy-complete zsh tmp.readpe.yaml  > readpe.zsh

rm tmp.readpe.yaml

