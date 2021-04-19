
PySoundCard can play and record audio.

Audio devices are supported through PortAudio_, which is a free,
cross-platform, open-source audio I/O library that runs on many
operating systems including Windows, OS X and Linux. It is
accessed through CFFI_, which is a foreign function interface for
Python calling C code. CFFI is supported for CPython 2.6+, 3.x and
PyPy 2.0+. PySoundCard represents audio data as NumPy arrays.

You must have PortAudio installed in order to run PySoundCard.

.. _PortAudio: http://www.portaudio.com/
.. _CFFI: http://cffi.readthedocs.org/


