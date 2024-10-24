# Imports

import time
from typing import Union, Any, get_origin, get_args

## Math

import math
import numpy as np
from numpy import ndarray

## Data

import csv
import pandas as pd
from pandas.core.frame import DataFrame

pd.set_option("display.max_colwidth",100)
pd.set_option("display.max_rows",100)

## Plots

import matplotlib.mlab as mlab
import matplotlib.pyplot as plt
from statsmodels.graphics.tsaplots import plot_acf 

plt.rcParams['figure.figsize'] = (10.0, 8.0)
plt.style.use('ggplot')

plt.rcParams['text.usetex'] = True  # Enable LaTeX rendering
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['Arial']

plt.rcParams['text.color'] = '#000000'
plt.rcParams['axes.labelcolor'] = '#000000'
plt.rcParams['xtick.color'] = '#000000'
plt.rcParams['ytick.color'] = '#000000'

a, b, c = 18, 20, 24
plt.rcParams['font.size'] = b            # sets the default font size
plt.rcParams['axes.labelsize'] = c       # for x and y labels 
plt.rcParams['axes.titlesize'] = c       # for subplot titles
plt.rcParams['xtick.labelsize'] = a      # for x-axis tick labels
plt.rcParams['ytick.labelsize'] = a      # for y-axis tick labels
plt.rcParams['legend.fontsize'] = b      # for legend text

plt.rcParams['axes.labelpad'] = 15