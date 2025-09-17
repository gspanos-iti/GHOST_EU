import sys
import time

"""
Functions for retrieving the monotonic clock.
"""
if sys.version_info >= (3, 3):
    import configparser
    get_timestamp = time.perf_counter  # just an alias with a better name
else:
    import ConfigParser as configparser
    import ctypes
    import ctypes.util
    import os

    try:
        #try:
        #    clock_gettime = ctypes.CDLL(ctypes.util.find_library('c'),
        #                                use_errno=True).clock_gettime
        #except Exception:
        #    clock_gettime = ctypes.CDLL(ctypes.util.find_library('rt'),
        #                                use_errno=True).clock_gettime

        class timespec(ctypes.Structure):
            """Time specification, as described in clock_gettime(3)."""
            _fields_ = (('tv_sec', ctypes.c_long),
                        ('tv_nsec', ctypes.c_long))

        if sys.platform.startswith('linux'):
            CLOCK_MONOTONIC = 1
        elif sys.platform.startswith('freebsd'):
            CLOCK_MONOTONIC = 4
        elif sys.platform.startswith('sunos5'):
            CLOCK_MONOTONIC = 4
        elif 'bsd' in sys.platform:
            CLOCK_MONOTONIC = 3
        elif sys.platform.startswith('aix'):
            CLOCK_MONOTONIC = ctypes.c_longlong(10)

        def monotonic():
            """Monotonic clock, cannot go backward."""
            ts = timespec()
            #if clock_gettime(CLOCK_MONOTONIC, ctypes.pointer(ts)):
            #    errno = ctypes.get_errno()
            #    raise OSError(errno, os.strerror(errno))
            return ts.tv_sec + ts.tv_nsec / 1.0e9

        # Perform a sanity-check.
        if monotonic() - monotonic() > 0:
            raise ValueError('monotonic() is not monotonic!')

    except Exception as e:
        raise RuntimeError('no suitable implementation for this system: ' +
                           repr(e))

    get_timestamp = monotonic


def get_configuration(filename):
    """
    Retrieve a configuration handler of a filename.
    """
    config = configparser.ConfigParser()
    config.read(filename)
    return config
