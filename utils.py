from threading import Thread
from functools import wraps
from time import sleep
from exceptions import *

intercept_events = ['http_request']


def event_packet_filter(event, **kwargs):
    if event not in intercept_events:
        raise EventNotSupported(event)
    if event == 'http_request':
        return "tcp and dst port 80 and src host {}".format(kwargs['ip'])


def async(func):

    @wraps(func)
    def async_func(*args, **kwargs):
        func_hl = Thread(target=func, args=args, kwargs=kwargs)
        func_hl.start()
        return func_hl
    return async_func


def post_sleep(sleep_time):
    def real_decorator(func):
        def inside(*args, **kwargs):
            func(*args, **kwargs)
            sleep(sleep_time)
        return inside
    return real_decorator
