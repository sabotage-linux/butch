#!/bin/sh
if [ -z "$1" ] ; then
	echo pass a tag as argv, i.e. v1.1.1
	exit 1
fi
tag=$1

git tag $tag
git push origin $tag

