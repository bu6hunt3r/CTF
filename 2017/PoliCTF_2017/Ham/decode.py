from scipy.io import wavfile
import numpy as np

rate, data = wavfile.read("filtered.wav")

# select the second channel

data = data[:,1]
# figure out how many samples should go into
# a single symbol, trim the signal to be a
# multiple of the symbol size (to reshape later);
# as the signal is not very long, it should be
# possible to cheat a little and merely cast
# the symbol size to int without corrections

samples_per_symbol = int(rate / 1000.0 * 32)
data = data[:-(data.size % samples_per_symbol)]

# split the signal into symbols, take
# the absolute values (so averaging won't
# just yield zeroes), then get the means

symbols = np.mean(np.abs(data.reshape(-1, samples_per_symbol)), axis=1)
# the first symbol must be "zero"; discard
# everything less than a half of its value
# to get rid of the trailing noise

symbols = symbols[symbols > (symbols[0] / 2)]

# now, taking the max value would get "one";
# averaging "one" and "zero" will give
# the approximate cutoff value

cutoff = np.mean([max(symbols), symbols[0]])

# turn the means into ones and zeroes

print ''.join(["1" if x else "0" for x in symbols > cutoff])