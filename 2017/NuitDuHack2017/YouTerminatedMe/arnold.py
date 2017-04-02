#!/usr/bin/env python

import PIL.Image
from numpy import *

#load image
im=array(PIL.Image.open("o.jpg"))
N=im.shape[0]

# create x and y components of Arnold's cat mapping
x,y=meshgrid(range(N),range(N))
xmap=(2*x+y) % N
ymap=(x+y) % N

for i in range(N+1):
	result=PIL.Image.fromarray(im)
	result.save("cat%03d.png" % i)
	im=im[xmap,ymap]
