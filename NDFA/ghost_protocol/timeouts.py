from blist import sorteddict
from ghost_protocol.utils import get_timestamp


class Timeouts:
    """
    Encapsulate a list of timeouts.

    This can be used as an engine to implement timers.
    """

    PROCESS_LIMIT = 100

    def __init__(self, next_handler=None):
        """

        Parameters:
          next_handler - optional handler to be called when the next handler
            changed.
            The handler takes one parameter, the next timeout if any or None.
        """

        self._timeouts = sorteddict()
        self._next_timeout = None
        self._next_handler = next_handler

    def get_next(self):
        """ Retrieves the next timeout. """
        return self._next_timeout

    def get_wait(self):
        """
        Retrieve the wait time in milliseconds.

        The method is used to compute how long is needed to wait until to call
        process method.

        Returns:
          wait time in milliseconds if any or None otherwise.
          The wait time can be 0 if process should be called immediately.
        """
        if self._next_timeout:
            wait_time = (self._next_timeout - get_timestamp()) * 1000
            if wait_time > 0:
                return wait_time
            else:
                return 0
        else:
            return None

    def add(self, timestamp, handler):
        """
        Add a timeout for a specified timestamp and handler.
        Multiple timeouts will be notified in the order of the used timestamp.
        If multiple timeouts are added for the same timestamp they will be
        notified in a random order.

        Arguments:
          timestamp - float - timestamp in seconds
          handler - a function without arguments that will be called on the
            specified timestamp
        """
        # if the timeouts is empty or next timeout is grater the timestamp
        # then set the next timeout with timer timeout
        if len(self._timeouts) == 0 or self._next_timeout > timestamp:
            self._next_timeout = timestamp
            if self._next_handler:
                self._next_handler(self._next_timeout)

        item = self._timeouts.get(timestamp)

        if item is None:
            self._timeouts[timestamp] = handler
        else:
            # if the item is a set then just add the hander to the set
            if type(item) is set:
                item.add(handler)
            else:
                # otherwise the item is a handler so replace it with a set to
                # store both handlers
                self._timeouts[timestamp] = set([item, handler])

    def remove(self, timestamp, handler):
        """
        Remove a previously added timeout.

        Arguments:
          timestamp - float - timestamp in seconds
          handler - the handler that was used when the timeout was added
        """
        item = self._timeouts.get(timestamp)
        remove = False  # flag indicating if we need to remove the entry
        if item:
            # if item is set then remove the handler
            if type(item) is set:
                item.discard(handler)
                if len(item) == 0:
                    # remove the entry only if there is no handler
                    remove = True
            # else the item is a handler and if equal to the specified handler
            # remove it
            elif item == handler:
                remove = True

            if remove:
                del self._timeouts[timestamp]
                # if we removed the first entry then update the next timeout
                if self._next_timeout == timestamp:
                    self._next_timeout = (next(iter(self._timeouts))
                                          if bool(self._timeouts) else None)
                    if self._next_handler:
                        self._next_handler(self._next_timeout)

    def clear(self):
        """ Remove all timeouts. """
        self._timeouts.clear()
        self._next_timeout = None
        if self._next_handler:
            self._next_handler(self._next_timeout)

    def process(self, maximum_count=PROCESS_LIMIT):
        """
        Process timeouts and update _next_timeout
        """
        if len(self._timeouts) == 0:
            return

        now = get_timestamp()

        count = 0

        item = self._timeouts.popitem()
        while item[0] <= now and count < maximum_count:

            # call the handler (if item is handler) or the handlers (if item
            # is a set)
            if type(item[1]) is set:
                for handler in item[1]:
                    handler()
                    count += 1
            else:
                item[1]()
                count += 1

            # if we reach the end of timeouts then return else get next item
            if len(self._timeouts) == 0:
                # next timeout is None since there are no timeouts
                self._next_timeout = None
                if self._next_handler:
                    self._next_handler(self._next_timeout)
                return
            else:
                item = self._timeouts.popitem()

        # put back the last retrieved item since has a timestamp higher then
        # now
        self._timeouts[item[0]] = item[1]
        # and update the _next_timeout
        self._next_timeout = item[0]
        if self._next_handler:
            self._next_handler(self._next_timeout)
