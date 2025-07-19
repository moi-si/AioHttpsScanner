import asyncio
import ssl
import os
import time
import logging
import contextvars
import uuid
import argparse
import ipaddress

from utils import *

conn_id = contextvars.ContextVar('connection_id', default='?')

class CustomLogRecord(logging.LogRecord):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.conn_id = conn_id.get()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(conn_id)s %(levelname)-8s %(message)s',
    datefmt="%Y-%m-%d %H:%M:%S"
)
logging.setLogRecordFactory(CustomLogRecord)

UA = 'Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0\r\n'

async def connect(ip, port, *, proxy_host, proxy_port, server_name, path, 
                  ignore_cert, host_header, save_when_200, save_when_30x, file_path_base):
    conn_id.set(str(uuid.uuid4())[:5])
    try:
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

        request = f'CONNECT {ip}:{port} HTTP/1.1\r\n\r\n'
        logging.info(request.rstrip('\r\n'))
        writer.write(request.encode())
        await writer.drain()

        header = await reader.readuntil(b'\r\n\r\n')
        status_line = header.decode().splitlines()[0]
        logging.info(status_line)
        status = status_line.split()[1]

        if status == '200':
            ssl_context = ssl.create_default_context()
            if ignore_cert:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            await start_tls(writer, ssl_context, server_hostname=server_name)
            request = (f'HEAD {path} HTTP/1.1\r\n'
                       f'Host: {host_header or server_name}\r\n'
                       'Connection: close\r\n'
                       f'User-Agent: {UA}\r\n'
                       '\r\n').encode()
            writer.write(request)
            await writer.drain()

            response_data = bytearray()
            while (data := await reader.read(16384)):
                response_data += data
            response = response_data.decode(errors='replace')
            status_line = response.splitlines()[0]
            logging.info(status_line)
            status_code = status_line.split()[1]
            if (save_when_200 and status_code == '200') or (save_when_30x and status_code.startswith('3')):
                dir_path = f'{file_path_base}{status_code}/'
                os.makedirs(dir_path, exist_ok=True)
                safe_ip = ip.replace(':', '.')
                file_path = f'{dir_path}{safe_ip}_{port}.txt'
                logging.info('Response will be written to %s', file_path)
                await to_thread(write_to_file, file_path, response)
                logging.info('Saved response')
    except Exception as e:
        logging.error(repr(e), exc_info=True)
    finally:
        if 'writer' in locals():
            writer.close()
            await writer.wait_closed()

async def scan(connections, max_concurrency, timeout, connect_kwargs):
    semaphore = asyncio.Semaphore(max_concurrency)
    async def sem_task(args):
        async with semaphore:
            await asyncio.wait_for(connect(*args, **connect_kwargs), timeout=timeout)
    tasks = [asyncio.create_task(sem_task(args)) for args in connections]
    await asyncio.gather(*tasks)

def main():
    parser = argparse.ArgumentParser(description='AioHttpsHunter')
    parser.add_argument('--proxy-host', metavar='host', required=True, type=str, help='HTTP proxy host (required)')
    parser.add_argument('--proxy-port', metavar='port', required=True, type=int, help='HTTP proxy port (required)')
    parser.add_argument('--url', metavar='url', required=True, type=str, help='Target HTTPS URL (required)')
    parser.add_argument('--host-header', metavar='host', type=str, help='Set the HTTP Host Header sent to the target host')
    parser.add_argument('--ip-range', metavar='range', required=True, type=str, help='IP range (required)')
    parser.add_argument('--start-port', metavar='port', required=True, type=int, help='Starting port to scan')
    parser.add_argument('--end-port', metavar='port', type=int, help='Ending port to scan (not inclusive)')
    parser.add_argument('--max-concur', metavar='num', type=int, default=20, help='Max concurrency (default: 20)')
    parser.add_argument('--timeout', metavar='sec', type=int, default=60, help='Timeout for each connection (default: 60)')
    parser.add_argument('--ignore-cert', default=False, action='store_true', help='Ignore certificate errors')
    parser.add_argument('--save-200', action='store_true', default=True, help='Save response if status is 200')
    parser.add_argument('--save-30x', action='store_true', help='Save response if status is 30x')

    args = parser.parse_args()

    if not args.url.startswith('https://'):
        raise ValueError('url must start with https://')
    url_rest = args.url[8:]
    if '/' in url_rest:
        server_name, path = url_rest.split('/', 1)
        path = '/' + path
    else:
        server_name, path = url_rest, '/'

    ips = (str(ip) for ip in ipaddress.ip_network(args.ip_range).hosts())

    if args.end_port:
        ports = range(args.start_port, args.end_port)
    else:
        ports = (args.start_port,)

    file_path_base = f"{int(time.time())}/"
    connections = [(ip, port) for ip in ips for port in ports]

    connect_kwargs = dict(
        proxy_host=args.proxy_host,
        proxy_port=args.proxy_port,
        server_name=server_name,
        path=path,
        ignore_cert=args.ignore_cert,
        host_header=args.host_header,
        save_when_200=args.save_200,
        save_when_30x=args.save_30x,
        file_path_base=file_path_base
    )

    asyncio.run(scan(connections, args.max_concur, args.timeout, connect_kwargs))

if __name__ == '__main__':
    main()
