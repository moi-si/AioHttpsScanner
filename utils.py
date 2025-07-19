import asyncio
import contextvars
import functools

async def to_thread(func, /, *args, **kwargs):
    """Asynchronously run function *func* in a separate thread.

    Any *args and **kwargs supplied for this function are directly passed
    to *func*. Also, the current :class:`contextvars.Context` is propagated,
    allowing context variables from the main thread to be accessed in the
    separate thread.

    Return a coroutine that can be awaited to get the eventual result of *func*.
    """
    loop = asyncio.get_running_loop()
    ctx = contextvars.copy_context()
    func_call = functools.partial(ctx.run, func, *args, **kwargs)
    return await loop.run_in_executor(None, func_call)

async def start_tls(writer: asyncio.StreamWriter,
                    sslcontext, *,
                    server_hostname=None,
                    ssl_handshake_timeout=None,
                    ssl_shutdown_timeout=None):
    protocol = writer._protocol
    server_side = protocol._client_connected_cb is not None
    await writer.drain()
    new_transport = await writer._loop.start_tls(
        writer._transport, protocol, sslcontext,
        server_side=server_side, server_hostname=server_hostname,
        ssl_handshake_timeout=ssl_handshake_timeout,
        ssl_shutdown_timeout=ssl_shutdown_timeout)
    writer._trasnsport = new_transport

    loop = protocol._loop
    protocol._transport = new_transport
    protocol._over_ssl = new_transport.get_extra_info('sslcontext') is not None

def write_to_file(path, data):
    with open(path, 'w+', encoding='utf-8', errors='replace') as f:
        f.write(data)
