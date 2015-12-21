
class DeviceNotFoundException(Exception):

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class EventNotSupported(Exception):

    def __init__(self, event):
        self.event = event

    def __str__(self):
        return "Event {} is not supported".format(self.event)
